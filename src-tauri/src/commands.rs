//! The API the UI calls. Every command returns `Result<_, String>` so failures
//! arrive in the front end as a readable sentence rather than a stack trace.

use std::path::Path;
use std::sync::Arc;

use tauri::{AppHandle, Emitter, State};

use crate::model::{
    AuthMethod, CommandResult, KeyChoice, KeyInfo, KeyNotice, KnownHost, KnownHostRef, ProbeStatus,
    Profile, SessionStatus, SetupResult, SshHostEntry, SshLocation, Tunnel,
};
use crate::state::{AppState, LiveSession};
use crate::{ezconfig, keys, knownhosts, restore, ssh, sshconfig, store, terminal};

/// Turn any error into the string the UI shows. `{:#}` includes anyhow's context chain.
fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn anyhow_err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

/// Push the current status of one profile to the UI.
async fn emit_status(app: &AppHandle, state: &AppState, profile_id: &str) {
    let inner = state.inner.lock().await;
    let Some(profile) = inner.profile(profile_id) else {
        return;
    };
    let status = match inner.sessions.get(profile_id) {
        Some(live) => live.status(profile).await,
        None => SessionStatus {
            profile_id: profile_id.to_string(),
            connected: false,
            degraded: false,
            server_fingerprint: None,
            first_contact: false,
            tunnels: Vec::new(),
        },
    };
    let _ = app.emit("session-status", status);
}

// ---------------------------------------------------------------- profiles

#[tauri::command]
pub async fn list_profiles(state: State<'_, AppState>) -> Result<Vec<Profile>, String> {
    Ok(state.inner.lock().await.profiles.clone())
}

#[tauri::command]
pub async fn save_profile(
    state: State<'_, AppState>,
    mut profile: Profile,
) -> Result<Profile, String> {
    if profile.host.trim().is_empty() {
        return Err("a host name or IP address is required".into());
    }
    if profile.username.trim().is_empty() {
        return Err("a user name is required".into());
    }
    if profile.auth == AuthMethod::Key && profile.key_path.as_deref().unwrap_or("").is_empty() {
        return Err("choose a private key, or switch this connection to password".into());
    }
    if profile.name.trim().is_empty() {
        profile.name = profile.host.clone();
    }
    if profile.id.is_empty() {
        profile.id = uuid::Uuid::new_v4().to_string();
    }

    // Two tunnels on the same local port would make the second one fail at bind time.
    let mut seen = std::collections::HashSet::new();
    for t in &profile.tunnels {
        if !seen.insert(t.local_port) {
            return Err(format!(
                "local port {} is used by more than one tunnel in this connection",
                t.local_port
            ));
        }
        // Refuse it here rather than discovering it in the config file: this
        // is written as a `LocalForward` line, and one ssh cannot parse stops
        // ssh reading the whole file — every connection on the machine, not
        // just this one.
        if !ezconfig::is_forwardable_host(&t.remote_host) {
            return Err(format!(
                "\"{}\" is not an address the server can be asked to reach. \
                 Give the tunnel \"{}\" a host name or IP as the server sees it \
                 — \"localhost\", not a full URL.",
                t.remote_host.trim(),
                t.name
            ));
        }
    }

    // Editing an entry that came from the ssh config makes it the user's own,
    // so their changes survive a refresh instead of being rebuilt away.
    profile.from_config = false;
    profile.customized = true;

    let mut inner = state.inner.lock().await;
    match inner.profile_mut(&profile.id) {
        Some(existing) => *existing = profile.clone(),
        None => inner.profiles.push(profile.clone()),
    }
    inner.persist().map_err(err)?;
    Ok(profile)
}

#[tauri::command]
pub async fn delete_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<(), String> {
    {
        let inner = state.inner.lock().await;
        if let Some(p) = inner.profile(&profile_id) {
            if p.from_config {
                return Err(format!(
                    "\"{}\" comes from {}. Remove its Host block from that file to stop it appearing here.",
                    p.name,
                    sshconfig::config_path_for(&inner.ssh_dir()).display()
                ));
            }
        }
    }

    // Tear the live session down first so we do not leak listening ports.
    disconnect(app, state.clone(), profile_id.clone())
        .await
        .ok();

    let mut inner = state.inner.lock().await;
    inner.profiles.retain(|p| p.id != profile_id);
    inner.persist().map_err(err)?;
    Ok(())
}

// -------------------------------------------------------------------- keys

#[tauri::command]
pub async fn list_keys(state: State<'_, AppState>) -> Result<Vec<KeyInfo>, String> {
    let dir = state.inner.lock().await.ssh_dir();
    keys::list_keys_in(&dir).map_err(anyhow_err)
}

#[tauri::command]
pub async fn generate_key(
    state: State<'_, AppState>,
    name: String,
    algorithm: String,
    comment: String,
    passphrase: Option<String>,
) -> Result<KeyInfo, String> {
    let dir = state.inner.lock().await.ssh_dir();
    keys::generate(&dir, &name, &algorithm, &comment, passphrase.as_deref()).map_err(anyhow_err)
}

/// Take whatever the user picked in the file dialog and make it usable.
///
/// Deliberately forgiving about what "a key" is: the public half resolves to
/// the private key beside it, a `.pem` from AWS is as good as an OpenSSH key,
/// and a key the system `ssh` would refuse for its permissions is tightened —
/// or copied into the `.ssh` directory at `0600` when it lives somewhere we
/// should not be rewriting, like the downloads folder. `note` says what was
/// done, when anything was.
#[tauri::command]
pub async fn use_key_file(state: State<'_, AppState>, path: String) -> Result<KeyChoice, String> {
    let dir = state.inner.lock().await.ssh_dir();
    let chosen = keys::use_key(&dir, Path::new(&path)).map_err(anyhow_err)?;
    Ok(KeyChoice {
        key: chosen.key,
        note: chosen.note,
    })
}

/// Put a key's permissions right on the way to using it, and say so.
///
/// Every route to using a key goes through here — connecting, installing the
/// key on a server, opening a terminal — because a key easySSH once tightened
/// can go loose again at any time: dragged into `~/.ssh` in the Finder,
/// restored from a backup, unzipped, copied off another machine. easySSH's own
/// connection would still work, and only the terminal would break, with an
/// error from `ssh` that names a mode the user never chose.
///
/// Never fails a connection: a key we could not tighten is still a key russh
/// can use, so the user is told and the attempt goes ahead.
fn tidy_key(app: &AppHandle, path: &str) {
    let notice = match keys::fix_permissions(Path::new(path)) {
        Ok(None) => return,
        Ok(Some(message)) => KeyNotice {
            path: path.to_string(),
            message,
            fixed: true,
        },
        Err(e) => KeyNotice {
            path: path.to_string(),
            message: format!("{e}"),
            fixed: false,
        },
    };
    let _ = app.emit("key-notice", notice);
}

/// Tighten a key the user was warned about in the picker.
#[tauri::command]
pub async fn fix_key_permissions(app: AppHandle, path: String) -> Result<KeyInfo, String> {
    keys::fix_permissions(Path::new(&path)).map_err(anyhow_err)?;
    let _ = app.emit("keys-changed", ());
    keys::inspect_path(&path).map_err(anyhow_err)
}

/// The `ssh-rsa AAAA... comment` line for a key, so the user can copy it.
#[tauri::command]
pub async fn public_key_text(path: String) -> Result<String, String> {
    keys::authorized_keys_line(Path::new(&path)).map_err(anyhow_err)
}

// ------------------------------------------------------------- connecting

#[tauri::command]
pub async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    secret: Option<String>,
) -> Result<SessionStatus, String> {
    let (profile, known_hosts) = {
        let inner = state.inner.lock().await;
        if inner.sessions.contains_key(&profile_id) {
            return Err("that connection is already open".into());
        }
        let profile = inner
            .profile(&profile_id)
            .ok_or("that connection no longer exists")?
            .clone();
        (profile, knownhosts::path_for(&inner.ssh_dir()))
    };

    if profile.auth == AuthMethod::Key {
        if let Some(path) = profile.key_path.as_deref() {
            tidy_key(&app, path);
        }
    }

    let session = ssh::connect_profile(&profile, secret.as_deref(), &known_hosts)
        .await
        .map_err(anyhow_err)?;
    let remote_description = ssh::describe_remote(&session.handle).await;

    // The secret goes with the session so the tunnel supervisor can rebuild it
    // after the transport drops without prompting the user again. In memory
    // only, and gone the moment they disconnect.
    let mut live = LiveSession::new(session, remote_description, secret);

    // Bring up anything marked auto-start. A tunnel that cannot bind is reported
    // but does not fail the connection itself.
    let auto: Vec<Tunnel> = profile
        .tunnels
        .iter()
        .filter(|t| t.auto_start)
        .cloned()
        .collect();
    for spec in auto {
        match spawn_tunnel(&app, &live, spec.clone(), None).await {
            Ok(running) => {
                // Only a forward that actually came up is one to put back later.
                // Marking a failed start as wanted would make the restore lamp
                // go red over a tunnel that never worked in the first place,
                // which is a different problem with a different fix — and the
                // error below already says so.
                live.desired.insert(spec.id.clone());
                live.tunnels.insert(spec.id.clone(), running);
            }
            Err(e) => {
                live.tunnel_errors.lock().await.insert(spec.id.clone(), e);
            }
        }
    }

    let mut inner = state.inner.lock().await;
    if inner.sessions.contains_key(&profile_id) {
        // Another connect for this profile finished while this one was in its
        // handshake. Keep that one and hang this one up: overwriting it would
        // drop its forwards without stopping them — `RunningTunnel` does not
        // stop on drop — leaving their local ports held for good.
        drop(inner);
        for (_, t) in live.tunnels {
            t.stop();
        }
        ssh::disconnect(&live.session.handle).await;
        return Err("that connection is already open".into());
    }
    // Deliberately not adopted: connecting to a host defined in the ssh config
    // must not copy it into profiles.json, or deleting its `Host` block later
    // would leave a connection here that nothing can remove.
    if let Some(p) = inner.profile_mut(&profile_id) {
        p.last_connected = Some(store::now());
    }
    // A session opened with a key is proof that passwordless login works, so a
    // connection whose key easySSH did not install itself counts as set up.
    let proven = match (profile.auth, profile.key_path.as_deref()) {
        (AuthMethod::Key, Some(k)) => inner.record_working_key(&profile_id, k),
        _ => false,
    };
    let _ = inner.persist();

    let status = live.status(&profile).await;
    inner.sessions.insert(profile_id, live);
    drop(inner);

    if proven {
        let _ = app.emit("profiles-changed", ());
    }
    let _ = app.emit("session-status", status.clone());
    Ok(status)
}

/// Start a forward on a session, wiring its late errors back into that
/// session's error map. The mechanics live in `restore`, which rebuilds
/// forwards on its own too, so both paths behave identically.
async fn spawn_tunnel(
    app: &AppHandle,
    live: &LiveSession,
    spec: Tunnel,
    counter: Option<Arc<std::sync::atomic::AtomicU64>>,
) -> Result<crate::tunnels::RunningTunnel, String> {
    restore::spawn(
        app,
        live.session.handle.clone(),
        live.tunnel_errors.clone(),
        spec,
        counter,
    )
    .await
}

#[tauri::command]
pub async fn disconnect(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<(), String> {
    let live = state.inner.lock().await.sessions.remove(&profile_id);
    if let Some(live) = live {
        for (_, tunnel) in live.tunnels {
            tunnel.stop();
        }
        ssh::disconnect(&live.session.handle).await;
    }
    emit_status(&app, &state, &profile_id).await;
    Ok(())
}

#[tauri::command]
pub async fn session_statuses(state: State<'_, AppState>) -> Result<Vec<SessionStatus>, String> {
    let inner = state.inner.lock().await;
    let mut out = Vec::new();
    for profile in &inner.profiles {
        let status = match inner.sessions.get(&profile.id) {
            Some(live) => live.status(profile).await,
            None => SessionStatus {
                profile_id: profile.id.clone(),
                connected: false,
                degraded: false,
                server_fingerprint: None,
                first_contact: false,
                tunnels: Vec::new(),
            },
        };
        out.push(status);
    }
    Ok(out)
}

#[tauri::command]
pub async fn remote_description(
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<String, String> {
    let inner = state.inner.lock().await;
    Ok(inner
        .sessions
        .get(&profile_id)
        .map(|s| s.remote_description.clone())
        .unwrap_or_default())
}

// ------------------------------------------------------- first-run key setup

/// Find out whether this connection already logs in without a password,
/// before asking the user for one.
///
/// Offers the connection's own key and then the other keys in the `.ssh`
/// directory. When one works, the connection is switched to it and marked as
/// set up, and its path is returned; `None` means the user does need to run
/// Set Up. Trusts a host on first use, like connecting does: the user asked.
#[tauri::command]
pub async fn detect_passwordless(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<Option<String>, String> {
    let (profile, ssh_dir) = {
        let inner = state.inner.lock().await;
        let profile = inner
            .profile(&profile_id)
            .ok_or("that connection no longer exists")?
            .clone();
        (profile, inner.ssh_dir())
    };
    let known_hosts = knownhosts::path_for(&ssh_dir);

    match crate::probe::key_auth(
        &profile,
        &ssh_dir,
        &known_hosts,
        ssh::HostKeyPolicy::LearnUnknown,
    )
    .await
    {
        crate::probe::KeyAuth::Works(path) => {
            let path = path.to_string_lossy().to_string();
            let changed = state
                .inner
                .lock()
                .await
                .record_working_key(&profile_id, &path);
            if changed {
                let _ = app.emit("profiles-changed", ());
            }
            Ok(Some(path))
        }
        // "No key works" and "could not tell" both mean: go ahead with Set Up.
        // A host that is down will fail there with a clearer message.
        _ => Ok(None),
    }
}

/// The headline flow: connect with a password, put our public key on the
/// remote, and flip the profile over to key authentication.
#[tauri::command]
pub async fn setup_key_auth(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    password: String,
    key_path: Option<String>,
) -> Result<SetupResult, String> {
    let (profile, known_hosts) = {
        let inner = state.inner.lock().await;
        let profile = inner
            .profile(&profile_id)
            .ok_or("that connection no longer exists")?
            .clone();
        (profile, knownhosts::path_for(&inner.ssh_dir()))
    };

    // Use the key the user picked; otherwise fall back to easySSH's own key,
    // generating it if this is the first time.
    let key = match key_path {
        Some(p) if !p.is_empty() => keys::inspect_path(&p).map_err(anyhow_err)?,
        _ => {
            let dir = state.inner.lock().await.ssh_dir();
            keys::ensure_default_key(&dir).map_err(anyhow_err)?
        }
    };
    tidy_key(&app, &key.path);
    let public_key = keys::authorized_keys_line(Path::new(&key.path)).map_err(anyhow_err)?;

    // The server may already accept this key. Then there is nothing to install
    // and no reason to have used the password at all.
    if !key.encrypted {
        let probe = ssh::find_working_key(
            &profile.host,
            profile.port,
            &profile.username,
            &[std::path::PathBuf::from(&key.path)],
            &known_hosts,
            ssh::HostKeyPolicy::LearnUnknown,
        )
        .await;
        if let Ok(Some((_, session))) = probe {
            ssh::disconnect(&session.handle).await;
            // Same outcome as a completed Set Up, including taking the
            // connection over from the ssh config: the user asked for this.
            let mut inner = state.inner.lock().await;
            inner.adopt(&profile_id);
            inner.record_working_key(&profile_id, &key.path);
            inner.persist().map_err(err)?;
            drop(inner);
            let _ = app.emit("profiles-changed", ());
            return Ok(SetupResult {
                installed: true,
                already_present: true,
                already_worked: true,
                key_path: key.path,
                public_key,
                server_fingerprint: session.fingerprint,
                remote_message: String::new(),
            });
        }
    }

    let session = ssh::connect_password(
        &profile.host,
        profile.port,
        &profile.username,
        &password,
        &known_hosts,
    )
    .await
    .map_err(anyhow_err)?;

    let (already_present, remote_message) = ssh::install_public_key(&session.handle, &public_key)
        .await
        .map_err(anyhow_err)?;

    ssh::disconnect(&session.handle).await;

    // Verify by actually authenticating with the key, so we never claim success
    // on a host where, say, PubkeyAuthentication is turned off.
    let verify = ssh::connect_key(
        &profile.host,
        profile.port,
        &profile.username,
        Path::new(&key.path),
        None,
        &known_hosts,
        // The install just ran over a live session to this host, so its key is
        // already recorded; learning is the right policy for a user-driven step.
        ssh::HostKeyPolicy::LearnUnknown,
    )
    .await;

    match verify {
        Ok(s) => ssh::disconnect(&s.handle).await,
        Err(e) => {
            return Err(format!(
                "The key was written to the remote, but logging in with it still failed: {e:#}. \
                 The server may have PubkeyAuthentication disabled, or ~/{} may be on a read-only \
                 or wrongly-owned home directory.",
                ".ssh/authorized_keys"
            ))
        }
    }

    let mut inner = state.inner.lock().await;
    inner.adopt(&profile_id);
    if let Some(p) = inner.profile_mut(&profile_id) {
        p.auth = AuthMethod::Key;
        p.key_path = Some(key.path.clone());
        p.key_installed = true;
    }
    inner.persist().map_err(err)?;
    drop(inner);

    let _ = app.emit("profiles-changed", ());

    Ok(SetupResult {
        installed: true,
        already_present,
        already_worked: false,
        key_path: key.path,
        public_key,
        server_fingerprint: session.fingerprint,
        remote_message,
    })
}

// ----------------------------------------------------------------- tunnels

#[tauri::command]
pub async fn start_tunnel(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    tunnel_id: String,
) -> Result<(), String> {
    let spec = {
        let inner = state.inner.lock().await;
        inner
            .profile(&profile_id)
            .ok_or("that connection no longer exists")?
            .tunnels
            .iter()
            .find(|t| t.id == tunnel_id)
            .ok_or("that tunnel no longer exists")?
            .clone()
    };

    // Snapshot what the forward needs and let go of the lock before binding, so
    // starting a tunnel never holds up the rest of the app — the restore sweep
    // included.
    let (handle, errors, counter) = {
        let inner = state.inner.lock().await;
        let live = inner
            .sessions
            .get(&profile_id)
            .ok_or("connect to the host before starting a tunnel")?;
        if live.tunnels.get(&tunnel_id).map(|t| t.is_alive()) == Some(true) {
            return Err("that tunnel is already running".into());
        }
        (
            live.session.handle.clone(),
            live.tunnel_errors.clone(),
            // Carry the count forward when this is a dead forward being
            // started again rather than a brand new one.
            live.tunnels.get(&tunnel_id).map(|t| t.connections.clone()),
        )
    };
    let running = restore::spawn(&app, handle, errors, spec, counter).await?;

    {
        let mut inner = state.inner.lock().await;
        if let Some(live) = inner.sessions.get_mut(&profile_id) {
            if live.tunnels.get(&tunnel_id).is_some_and(|t| t.is_alive()) {
                // Something else brought it up while we were binding; ours
                // cannot have won the port, but stop it all the same.
                running.stop();
                return Err("that tunnel is already running".into());
            }
            if let Some(old) = live.tunnels.remove(&tunnel_id) {
                old.stop();
            }
            live.tunnel_errors.lock().await.remove(&tunnel_id);
            // Switching a forward on is what marks it as wanted, which is what
            // lets the supervisor tell a tunnel that broke from one the user
            // turned off.
            live.desired.insert(tunnel_id.clone());
            live.tunnels.insert(tunnel_id, running);
        } else {
            running.stop();
            return Err("the session closed while the tunnel was starting".into());
        }
    }

    emit_status(&app, &state, &profile_id).await;
    Ok(())
}

#[tauri::command]
pub async fn stop_tunnel(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    tunnel_id: String,
) -> Result<(), String> {
    {
        let mut inner = state.inner.lock().await;
        let live = inner
            .sessions
            .get_mut(&profile_id)
            .ok_or("that connection is not open")?;
        if let Some(t) = live.tunnels.remove(&tunnel_id) {
            t.stop();
        }
        live.tunnel_errors.lock().await.remove(&tunnel_id);
        // No longer wanted, so the supervisor leaves it alone. Its restore
        // history goes too: the next time the user starts it, the lamp should
        // describe that run and not the last one.
        live.desired.remove(&tunnel_id);
        live.restores.remove(&tunnel_id);
    }
    emit_status(&app, &state, &profile_id).await;
    Ok(())
}

/// Check this connection now and rebuild whatever has stopped working, rather
/// than waiting for the next sweep.
///
/// Exposed because the supervisor's timer is deliberately unhurried, and a user
/// who is already staring at a page that will not load should not have to wait
/// out an interval chosen to be gentle on the server.
#[tauri::command]
pub async fn restore_tunnels(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<(), String> {
    if !state.inner.lock().await.sessions.contains_key(&profile_id) {
        return Err("that connection is not open".into());
    }
    restore::sweep_now(&app, &profile_id).await;
    Ok(())
}

/// Turn the tunnel supervisor on or off.
#[tauri::command]
pub async fn set_auto_restore_tunnels(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    let mut inner = state.inner.lock().await;
    inner.settings.auto_restore_tunnels = enabled;
    store::save_settings(&inner.settings).map_err(err)
}

// ----------------------------------------------------------------- about

/// The version this build was compiled from, for the sidebar's wordmark.
/// Taken from `Cargo.toml`, which `tauri.conf.json` is kept in step with, so
/// there is one number to bump and no copy in the front end to drift.
#[tauri::command]
pub fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ---------------------------------------------------------------- terminal

#[tauri::command]
pub async fn open_terminal(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    include_tunnels: bool,
) -> Result<String, String> {
    let (profile, forwarded) = {
        let inner = state.inner.lock().await;
        let profile = inner
            .profile(&profile_id)
            .ok_or("that connection no longer exists")?
            .clone();
        let forwarded = live_forwarded_ports(&inner, &profile);
        (profile, forwarded)
    };
    // The system ssh is about to take over, and unlike russh it refuses a key
    // anyone else can read. This is the moment that matters most.
    if profile.auth == AuthMethod::Key {
        if let Some(path) = profile.key_path.as_deref() {
            tidy_key(&app, path);
        }
    }
    terminal::open(&profile, include_tunnels, &forwarded).map_err(anyhow_err)
}

/// The local ports this connection is already forwarding from inside easySSH.
///
/// The terminal must leave these alone: a second `ssh -L` on the same port
/// cannot bind, and if the terminal gets there first the app's own tunnel is
/// the one that fails.
fn live_forwarded_ports(inner: &crate::state::Inner, profile: &Profile) -> Vec<u16> {
    let Some(live) = inner.sessions.get(&profile.id) else {
        return Vec::new();
    };
    profile
        .tunnels
        .iter()
        .filter(|t| live.tunnels.get(&t.id).map(|r| r.is_alive()) == Some(true))
        .map(|t| t.local_port)
        .collect()
}

/// The exact command the terminal button would run, shown in the UI.
#[tauri::command]
pub async fn terminal_preview(
    state: State<'_, AppState>,
    profile_id: String,
    include_tunnels: bool,
) -> Result<String, String> {
    let inner = state.inner.lock().await;
    let profile = inner
        .profile(&profile_id)
        .ok_or("that connection no longer exists")?;
    let forwarded = live_forwarded_ports(&inner, profile);
    Ok(terminal::ssh_command_line(
        profile,
        include_tunnels,
        &forwarded,
    ))
}

/// Run an arbitrary command on an open session — used by the quick command bar.
#[tauri::command]
pub async fn run_command(
    state: State<'_, AppState>,
    profile_id: String,
    command: String,
) -> Result<CommandResult, String> {
    let command = command.trim().to_string();
    if command.is_empty() {
        return Err("type a command to run".into());
    }

    // Take the handle and release the lock: a long-running command must not
    // block status polling or another connection for its whole duration.
    let handle = {
        let inner = state.inner.lock().await;
        inner
            .sessions
            .get(&profile_id)
            .ok_or("connect to the host first")?
            .session
            .handle
            .clone()
    };

    let out = ssh::exec(&handle, &command).await.map_err(anyhow_err)?;
    Ok(CommandResult {
        code: out.code,
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

// ------------------------------------------------- ssh config locations

/// Every `.ssh` directory easySSH can see on this machine.
#[tauri::command]
pub async fn list_ssh_locations(state: State<'_, AppState>) -> Result<Vec<SshLocation>, String> {
    let pinned = state.inner.lock().await.settings.ssh_dir.clone();
    let mut locations = sshconfig::discover_locations();

    // A directory the user picked by hand belongs in the list even though it is
    // not one of the conventional spots.
    if let Some(dir) = pinned {
        if !dir.is_empty() && !locations.iter().any(|l| l.dir == dir) {
            locations.push(sshconfig::location_for_dir(Path::new(&dir)));
        }
    }
    Ok(locations)
}

/// The location currently in focus.
#[tauri::command]
pub async fn active_ssh_location(state: State<'_, AppState>) -> Result<SshLocation, String> {
    let dir = state.inner.lock().await.ssh_dir();
    Ok(sshconfig::location_for_dir(&dir))
}

/// Focus a different `.ssh` directory. Passing `None` returns to the default.
#[tauri::command]
pub async fn set_ssh_location(
    app: AppHandle,
    state: State<'_, AppState>,
    dir: Option<String>,
) -> Result<SshLocation, String> {
    // A directory that does not exist, or holds no config file, is a valid
    // choice — it simply contributes no connections. Refusing it here would
    // leave the previous location's hosts on screen under the new selection.
    let mut inner = state.inner.lock().await;
    inner.settings.ssh_dir = dir.filter(|d| !d.is_empty());
    store::save_settings(&inner.settings).map_err(err)?;
    inner.sync_config_profiles();
    let active = inner.ssh_dir();
    drop(inner);

    let _ = app.emit("profiles-changed", ());
    let _ = app.emit("ssh-location-changed", ());
    Ok(sshconfig::location_for_dir(&active))
}

/// Hosts defined in the active location's config file.
#[tauri::command]
pub async fn list_ssh_hosts(state: State<'_, AppState>) -> Result<Vec<SshHostEntry>, String> {
    let inner = state.inner.lock().await;
    let dir = inner.ssh_dir();
    sshconfig::hosts_for(&dir, &inner.profiles).map_err(anyhow_err)
}

/// The settings the front end needs to render: which `.ssh` directory is in
/// focus, and whether config hosts are listed.
#[tauri::command]
pub async fn app_settings(state: State<'_, AppState>) -> Result<crate::model::Settings, String> {
    Ok(state.inner.lock().await.settings.clone())
}

/// Copy a host defined in the user's ssh config into easySSH's own store.
///
/// Until this is done, a config host is shown but not owned: it is rebuilt
/// from the config on every refresh and vanishes with its `Host` block.
/// Importing writes it to `ez_config`, so it keeps tunnels, a colour and the
/// key easySSH installed for it.
#[tauri::command]
pub async fn import_ssh_host(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<Profile, String> {
    let mut inner = state.inner.lock().await;
    let profile = inner
        .profile_mut(&profile_id)
        .ok_or("that connection no longer exists")?;
    if !profile.from_config {
        return Err("that connection is already saved in easySSH".into());
    }
    // Remember where it came from so the alias, and the link back to the
    // user's config, survive the import.
    if profile.config_alias.is_none() {
        profile.config_alias = Some(profile.name.clone());
    }
    profile.from_config = false;
    profile.customized = true;
    let imported = profile.clone();

    inner.persist().map_err(err)?;
    drop(inner);

    let _ = app.emit("profiles-changed", ());
    Ok(imported)
}

/// Show or hide the hosts that come from the user's ssh config, leaving just
/// the connections easySSH owns.
#[tauri::command]
pub async fn set_show_config_hosts(
    app: AppHandle,
    state: State<'_, AppState>,
    show: bool,
) -> Result<(), String> {
    let mut inner = state.inner.lock().await;
    inner.settings.show_config_hosts = show;
    store::save_settings(&inner.settings).map_err(err)?;
    drop(inner);

    let _ = app.emit("profiles-changed", ());
    Ok(())
}

/// Write a profile into the active config file as a `Host` block, so
/// `ssh <alias>` works from any terminal afterwards.
#[tauri::command]
pub async fn add_to_ssh_config(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    alias: String,
    include_tunnels: bool,
) -> Result<String, String> {
    let (dir, profile) = {
        let inner = state.inner.lock().await;
        (
            inner.ssh_dir(),
            inner
                .profile(&profile_id)
                .ok_or("that connection no longer exists")?
                .clone(),
        )
    };

    let block =
        sshconfig::append_host(&dir, &alias, &profile, include_tunnels).map_err(anyhow_err)?;

    state.inner.lock().await.sync_config_profiles();
    let _ = app.emit("profiles-changed", ());
    let _ = app.emit("ssh-location-changed", ());
    Ok(block)
}

// ------------------------------------------------- native shell integration
//
// `withGlobalTauri` exposes only the core JS API, not the plugins' guest
// bindings, so the front end reaches these through our own commands instead.

/// Native "choose a private key" dialog. Returns `None` if the user cancelled.
#[tauri::command]
pub async fn pick_key_file(
    app: AppHandle,
    start_in: Option<String>,
    title: Option<String>,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    // No extension filter: an OpenSSH key has no extension at all, and a
    // filtered dialog would grey it out.
    let mut builder = app
        .dialog()
        .file()
        .set_title(title.unwrap_or_else(|| "Choose a private key".into()));
    if let Some(dir) = start_in.filter(|d| Path::new(d).is_dir()) {
        builder = builder.set_directory(dir);
    }

    // The dialog must run off the async command thread or it deadlocks the runtime.
    let picked = tauri::async_runtime::spawn_blocking(move || builder.blocking_pick_file())
        .await
        .map_err(|e| format!("the file dialog failed: {e}"))?;

    Ok(picked.map(|p| p.to_string()))
}

/// Open a URL in the user's default browser.
#[tauri::command]
pub async fn open_url(app: AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;

    // Only ever open a local forwarded port; never an arbitrary URL from the page.
    let parsed = url.trim();
    let allowed =
        parsed.starts_with("http://127.0.0.1:") || parsed.starts_with("https://127.0.0.1:");
    if !allowed {
        return Err(format!("refusing to open {parsed}"));
    }

    app.opener()
        .open_url(parsed, None::<&str>)
        .map_err(|e| format!("could not open {parsed}: {e}"))
}

// ------------------------------------------------------------- known hosts

/// Entries in the selected location's `known_hosts` file.
#[tauri::command]
pub async fn list_known_hosts(state: State<'_, AppState>) -> Result<Vec<KnownHost>, String> {
    let inner = state.inner.lock().await;
    let dir = inner.ssh_dir();
    knownhosts::list(&dir, &inner.profiles).map_err(anyhow_err)
}

/// Where that file is, so the UI can name it.
#[tauri::command]
pub async fn known_hosts_path(state: State<'_, AppState>) -> Result<String, String> {
    let dir = state.inner.lock().await.ssh_dir();
    Ok(knownhosts::path_for(&dir).display().to_string())
}

/// Delete the given entries. Returns how many lines were removed.
#[tauri::command]
pub async fn remove_known_hosts(
    state: State<'_, AppState>,
    entries: Vec<KnownHostRef>,
) -> Result<usize, String> {
    let dir = state.inner.lock().await.ssh_dir();
    knownhosts::remove(&dir, &entries).map_err(anyhow_err)
}

/// The latest background health-check results, one per connection that has
/// been checked.
#[tauri::command]
pub async fn probe_statuses(state: State<'_, AppState>) -> Result<Vec<ProbeStatus>, String> {
    let inner = state.inner.lock().await;
    Ok(inner.probes.values().map(|r| r.status.clone()).collect())
}

// ------------------------------------------------------------------- files

/// The live SSH handle for a connection, or a sentence saying why not.
async fn live_handle(
    state: &AppState,
    profile_id: &str,
) -> Result<Arc<russh::client::Handle<ssh::Client>>, String> {
    state
        .inner
        .lock()
        .await
        .sessions
        .get(profile_id)
        .map(|live| live.session.handle.clone())
        .ok_or_else(|| "connect to the host first".to_string())
}

/// Forward transfer progress to the UI, at most ten times a second. A large
/// folder moves in thousands of chunks, and an event per chunk would only
/// flood the page with repaints nobody can see.
fn progress_reporter(
    app: &AppHandle,
    profile_id: &str,
    direction: &'static str,
) -> impl Fn(crate::transfer::Progress) {
    let app = app.clone();
    let profile_id = profile_id.to_string();
    let last = std::sync::Mutex::new((std::time::Instant::now(), ""));
    move |p: crate::transfer::Progress| {
        let mut last = last.lock().unwrap_or_else(|e| e.into_inner());
        let phase_changed = last.1 != p.phase;
        if !phase_changed && last.0.elapsed() < std::time::Duration::from_millis(100) {
            return;
        }
        *last = (std::time::Instant::now(), p.phase);
        let _ = app.emit(
            "transfer-progress",
            serde_json::json!({
                "profile_id": profile_id,
                "direction": direction,
                "phase": p.phase,
                "done": p.done,
                "total": p.total,
            }),
        );
    }
}

/// Send a local file or folder into a directory on the server.
#[tauri::command]
pub async fn send_path(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    local_path: String,
    remote_dir: String,
) -> Result<crate::transfer::Outcome, String> {
    let handle = live_handle(&state, &profile_id).await?;
    let progress = progress_reporter(&app, &profile_id, "send");
    crate::transfer::send(&handle, Path::new(&local_path), &remote_dir, progress)
        .await
        .map_err(anyhow_err)
}

/// Fetch a remote file or folder into a directory on this machine.
#[tauri::command]
pub async fn receive_path(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    remote_path: String,
    local_dir: String,
) -> Result<crate::transfer::Outcome, String> {
    if local_dir.trim().is_empty() {
        return Err("choose a folder on this computer to save into".into());
    }
    let handle = live_handle(&state, &profile_id).await?;
    let progress = progress_reporter(&app, &profile_id, "receive");
    crate::transfer::receive(&handle, &remote_path, Path::new(&local_dir), progress)
        .await
        .map_err(anyhow_err)
}

/// List a directory on the server, for browsing to a file or a destination.
#[tauri::command]
pub async fn list_remote_dir(
    state: State<'_, AppState>,
    profile_id: String,
    dir: String,
) -> Result<crate::transfer::RemoteListing, String> {
    let handle = live_handle(&state, &profile_id).await?;
    crate::transfer::list_remote(&handle, &dir)
        .await
        .map_err(anyhow_err)
}

/// Where received files go unless the user picks somewhere else.
#[tauri::command]
pub fn default_receive_dir() -> String {
    dirs::download_dir()
        .or_else(dirs::home_dir)
        .map(|d| d.display().to_string())
        .unwrap_or_default()
}

/// Ask the user for a file or a folder on this machine.
///
/// `kind` is `file` or `folder`. One dialog cannot offer both on every
/// platform, so the UI asks which the user means.
#[tauri::command]
pub async fn pick_local_path(
    app: AppHandle,
    kind: String,
    title: Option<String>,
    start_in: Option<String>,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let mut builder = app.dialog().file();
    if let Some(t) = title {
        builder = builder.set_title(t);
    }
    if let Some(dir) = start_in.filter(|d| Path::new(d).is_dir()) {
        builder = builder.set_directory(dir);
    }
    // The dialog must run off the async command thread or it deadlocks the runtime.
    let folder = kind == "folder";
    let picked = tauri::async_runtime::spawn_blocking(move || {
        if folder {
            builder.blocking_pick_folder()
        } else {
            builder.blocking_pick_file()
        }
    })
    .await
    .map_err(|e| format!("the file dialog failed: {e}"))?;
    Ok(picked.map(|p| p.to_string()))
}

// --------------------------------------------------------------- publishing

/// Tell the UI this connection's publication changed, and to fetch it again.
fn publish_changed(app: &AppHandle, profile_id: &str) {
    let _ = app.emit(
        "publish-changed",
        serde_json::json!({ "profile_id": profile_id }),
    );
}

/// Replace a publication's token when it runs out, and tell the UI, for as
/// long as the publication exists.
fn spawn_rotator(
    app: &AppHandle,
    profile_id: &str,
    shared: Arc<crate::publish::Shared>,
) -> tokio::task::JoinHandle<()> {
    let app = app.clone();
    let profile_id = profile_id.to_string();
    tokio::spawn(async move {
        loop {
            // A second past expiry, so `current` is sure to have rotated.
            tokio::time::sleep(shared.expires_in() + std::time::Duration::from_secs(1)).await;
            let _ = shared.current();
            publish_changed(&app, &profile_id);
        }
    })
}

/// What a connection is publishing, if anything.
#[tauri::command]
pub async fn publish_status(
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<Option<crate::publish::Status>, String> {
    let inner = state.inner.lock().await;
    Ok(inner
        .sessions
        .get(&profile_id)
        .and_then(|live| live.publication.as_ref())
        .map(|p| p.status(&profile_id)))
}

/// Start answering the server's requests: ask it to listen on its loopback
/// interface and send each connection back down this session.
async fn start_serving(state: &AppState, profile_id: &str) -> Result<(), String> {
    let (handle, slot, shared, running) = {
        let inner = state.inner.lock().await;
        let live = inner
            .sessions
            .get(profile_id)
            .ok_or("connect to the host first")?;
        let publication = live
            .publication
            .as_ref()
            .ok_or("choose a file or folder to publish first")?;
        (
            live.session.handle.clone(),
            live.session.publish.clone(),
            publication.shared.clone(),
            publication.remote_port,
        )
    };

    if let Ok(mut s) = slot.write() {
        *s = Some(shared);
    }
    if running.is_some() {
        return Ok(());
    }
    let port = handle.tcpip_forward("127.0.0.1", 0).await.map_err(|e| {
        format!(
            "the server would not open a port for the link ({e}). Its sshd may have \
                 AllowTcpForwarding or remote forwarding switched off."
        )
    })?;

    let mut inner = state.inner.lock().await;
    match inner
        .sessions
        .get_mut(profile_id)
        .and_then(|l| l.publication.as_mut())
    {
        Some(p) => {
            p.remote_port = Some(port);
            Ok(())
        }
        None => {
            // Cleared while we waited on the server; do not leave its port open.
            drop(inner);
            let _ = handle.cancel_tcpip_forward("127.0.0.1", port).await;
            Err("the publication was removed while it was starting".into())
        }
    }
}

/// Stop answering: close the server's port and forget what to serve, so even a
/// connection already on its way in finds nothing.
async fn stop_serving(state: &AppState, profile_id: &str) {
    let (handle, slot, port) = {
        let mut inner = state.inner.lock().await;
        let Some(live) = inner.sessions.get_mut(profile_id) else {
            return;
        };
        let port = live.publication.as_mut().and_then(|p| p.remote_port.take());
        (
            live.session.handle.clone(),
            live.session.publish.clone(),
            port,
        )
    };
    if let Ok(mut s) = slot.write() {
        *s = None;
    }
    if let Some(port) = port {
        let _ = handle.cancel_tcpip_forward("127.0.0.1", port).await;
    }
}

/// Publish a local file or folder on this connection, replacing whatever it
/// published before, and start serving it.
#[tauri::command]
pub async fn publish_choose(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    path: String,
) -> Result<crate::publish::Status, String> {
    let shared = Arc::new(crate::publish::Shared::new(Path::new(&path)).map_err(anyhow_err)?);
    {
        let mut inner = state.inner.lock().await;
        let live = inner
            .sessions
            .get_mut(&profile_id)
            .ok_or("connect to the host first")?;
        // Keep the server's port when swapping the item: the old link dies with
        // its token, and the new item is reachable at once.
        let port = live.publication.as_ref().and_then(|p| p.remote_port);
        live.publication = Some(crate::publish::Publication {
            rotator: Some(spawn_rotator(&app, &profile_id, shared.clone())),
            shared,
            remote_port: port,
        });
    }
    // Tell the UI either way: when the server refuses a port, the choice is
    // still made, and the UI must show it — switched off — so the user can see
    // what happened and try the switch again.
    let started = start_serving(&state, &profile_id).await;
    publish_changed(&app, &profile_id);
    started?;
    publish_status(state, profile_id)
        .await?
        .ok_or_else(|| "the publication disappeared".into())
}

/// Switch serving on or off, keeping the chosen file or folder.
///
/// Switching on issues a fresh token, so a link from an earlier run does not
/// quietly start working again.
#[tauri::command]
pub async fn publish_serving(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
    on: bool,
) -> Result<Option<crate::publish::Status>, String> {
    if on {
        {
            let inner = state.inner.lock().await;
            if let Some(p) = inner
                .sessions
                .get(&profile_id)
                .and_then(|l| l.publication.as_ref())
            {
                if p.remote_port.is_none() {
                    p.shared.rotate();
                }
            }
        }
        let started = start_serving(&state, &profile_id).await;
        publish_changed(&app, &profile_id);
        started?;
    } else {
        stop_serving(&state, &profile_id).await;
        publish_changed(&app, &profile_id);
    }
    publish_status(state, profile_id).await
}

/// Issue a new link now, invalidating the current one.
#[tauri::command]
pub async fn publish_new_link(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<Option<crate::publish::Status>, String> {
    {
        let inner = state.inner.lock().await;
        if let Some(p) = inner
            .sessions
            .get(&profile_id)
            .and_then(|l| l.publication.as_ref())
        {
            p.shared.rotate();
        }
    }
    publish_changed(&app, &profile_id);
    publish_status(state, profile_id).await
}

/// Stop publishing altogether and forget the chosen file or folder.
#[tauri::command]
pub async fn publish_clear(
    app: AppHandle,
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<(), String> {
    stop_serving(&state, &profile_id).await;
    if let Some(live) = state.inner.lock().await.sessions.get_mut(&profile_id) {
        live.publication = None;
    }
    publish_changed(&app, &profile_id);
    Ok(())
}
