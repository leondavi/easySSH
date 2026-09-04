//! The API the UI calls. Every command returns `Result<_, String>` so failures
//! arrive in the front end as a readable sentence rather than a stack trace.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use crate::model::{
    AuthMethod, CommandResult, KeyInfo, KnownHost, KnownHostRef, Profile, SessionStatus,
    SetupResult, SshHostEntry, SshLocation, Tunnel,
};
use crate::state::{AppState, LiveSession};
use crate::{keys, knownhosts, ssh, sshconfig, store, terminal, tunnels};

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
    store::save_profiles(&inner.profiles).map_err(err)?;
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
    store::save_profiles(&inner.profiles).map_err(err)?;
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

/// Validate a key the user picked with the file dialog.
#[tauri::command]
pub async fn inspect_key(path: String) -> Result<KeyInfo, String> {
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

    let session = ssh::connect_profile(&profile, secret.as_deref(), &known_hosts)
        .await
        .map_err(anyhow_err)?;
    let remote_description = ssh::describe_remote(&session.handle).await;

    let mut live = LiveSession {
        session,
        tunnels: HashMap::new(),
        tunnel_errors: Arc::new(Mutex::new(HashMap::new())),
        remote_description,
    };

    // Bring up anything marked auto-start. A tunnel that cannot bind is reported
    // but does not fail the connection itself.
    let auto: Vec<Tunnel> = profile
        .tunnels
        .iter()
        .filter(|t| t.auto_start)
        .cloned()
        .collect();
    for spec in auto {
        match spawn_tunnel(&app, &live, spec.clone()).await {
            Ok(running) => {
                live.tunnels.insert(spec.id.clone(), running);
            }
            Err(e) => {
                live.tunnel_errors.lock().await.insert(spec.id.clone(), e);
            }
        }
    }

    let mut inner = state.inner.lock().await;
    // Deliberately not adopted: connecting to a host defined in the ssh config
    // must not copy it into profiles.json, or deleting its `Host` block later
    // would leave a connection here that nothing can remove.
    if let Some(p) = inner.profile_mut(&profile_id) {
        p.last_connected = Some(store::now());
    }
    let _ = store::save_profiles(&inner.profiles);

    let status = live.status(&profile).await;
    inner.sessions.insert(profile_id, live);
    drop(inner);

    let _ = app.emit("session-status", status.clone());
    Ok(status)
}

/// Start a forward, wiring its late errors back into the session's error map.
async fn spawn_tunnel(
    app: &AppHandle,
    live: &LiveSession,
    spec: Tunnel,
) -> Result<tunnels::RunningTunnel, String> {
    let errors = live.tunnel_errors.clone();
    let id = spec.id.clone();
    let app = app.clone();
    tunnels::start(live.session.handle.clone(), spec, move |msg| {
        let errors = errors.clone();
        let id = id.clone();
        let app = app.clone();
        tokio::spawn(async move {
            errors.lock().await.insert(id.clone(), msg.clone());
            let _ = app.emit(
                "tunnel-error",
                serde_json::json!({ "id": id, "error": msg }),
            );
        });
    })
    .await
    .map_err(anyhow_err)
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
    let public_key = keys::authorized_keys_line(Path::new(&key.path)).map_err(anyhow_err)?;

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
    store::save_profiles(&inner.profiles).map_err(err)?;
    drop(inner);

    let _ = app.emit("profiles-changed", ());

    Ok(SetupResult {
        installed: true,
        already_present,
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

    let running = {
        let inner = state.inner.lock().await;
        let live = inner
            .sessions
            .get(&profile_id)
            .ok_or("connect to the host before starting a tunnel")?;
        if live.tunnels.get(&tunnel_id).map(|t| t.is_alive()) == Some(true) {
            return Err("that tunnel is already running".into());
        }
        spawn_tunnel(&app, live, spec).await?
    };

    {
        let mut inner = state.inner.lock().await;
        if let Some(live) = inner.sessions.get_mut(&profile_id) {
            live.tunnel_errors.lock().await.remove(&tunnel_id);
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
    }
    emit_status(&app, &state, &profile_id).await;
    Ok(())
}

// ---------------------------------------------------------------- terminal

#[tauri::command]
pub async fn open_terminal(
    state: State<'_, AppState>,
    profile_id: String,
    include_tunnels: bool,
) -> Result<String, String> {
    let profile = {
        let inner = state.inner.lock().await;
        inner
            .profile(&profile_id)
            .ok_or("that connection no longer exists")?
            .clone()
    };
    terminal::open(&profile, include_tunnels).map_err(anyhow_err)
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
    Ok(terminal::ssh_command_line(profile, include_tunnels))
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
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let mut builder = app.dialog().file().set_title("Choose a private key");
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
