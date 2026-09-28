//! Keeping forwards working without the user having to notice they stopped.
//!
//! # Why this exists
//!
//! A tunnel is a `TcpListener` on this machine plus a channel opened on the SSH
//! session for every connection that arrives. Those two halves fail
//! independently, and the local half is the durable one: when the SSH transport
//! dies — the laptop slept, the Wi-Fi changed, a NAT table forgot the flow,
//! `sshd` was restarted, a VPN dropped — the listener carries on accepting
//! perfectly happily and only the channel opens fail.
//!
//! From the outside that is the worst possible failure. The switch is still on,
//! the status still says the forward is running, the port still answers a TCP
//! connect, and the browser just hangs. The only cure was to disconnect and
//! reconnect, because that is the only thing that built a new session.
//!
//! So this module does three things on a timer:
//!
//! * asks each live session whether it can still open a channel at all
//!   (`ssh::healthy` — see there for why `is_closed` is not enough),
//! * rebuilds the session and every forward the user wants when it cannot,
//! * restarts individual forwards whose accept loop died while the session
//!   itself stayed up.
//!
//! Every outcome is recorded per tunnel so the UI can show whether a forward
//! has ever been rebuilt under the user, and whether the last attempt worked.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client::Handle;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::sync::Mutex;

use crate::model::Tunnel;
use crate::ssh::Client;
use crate::state::AppState;
use crate::tunnels::RunningTunnel;
use crate::{knownhosts, ssh, tunnels};

/// How long to wait for the local port to be released after aborting a forward's
/// accept loop, before giving up on rebinding it.
///
/// `RunningTunnel::stop` aborts the task, and the listener is only dropped when
/// the runtime gets round to it, so an immediate rebind of the same port loses a
/// race with the tunnel we just stopped ourselves.
const REBIND_PATIENCE: Duration = Duration::from_millis(1500);
const REBIND_INTERVAL: Duration = Duration::from_millis(50);

/// Waits between attempts to rebuild a session, indexed by consecutive failures.
///
/// A server that is genuinely down would otherwise get a full SSH handshake
/// every tick for as long as the app is open, which is both futile and the
/// pattern that gets a client rate-limited or banned.
pub fn backoff(consecutive_failures: u32) -> Duration {
    match consecutive_failures {
        0 | 1 => Duration::from_secs(15),
        2 => Duration::from_secs(45),
        3 => Duration::from_secs(120),
        _ => Duration::from_secs(300),
    }
}

/// Start one forward and wire its late errors back into the session's error map.
///
/// `counter` carries an earlier tunnel's connection count forward, so a rebuild
/// does not look like the port has never been used.
pub async fn spawn<R: Runtime>(
    app: &AppHandle<R>,
    handle: Arc<Handle<Client>>,
    errors: Arc<Mutex<HashMap<String, String>>>,
    spec: Tunnel,
    counter: Option<Arc<AtomicU64>>,
) -> Result<RunningTunnel, String> {
    let id = spec.id.clone();
    let app_for_errors = app.clone();
    let report = move |msg: String| {
        let errors = errors.clone();
        let id = id.clone();
        let app = app_for_errors.clone();
        tokio::spawn(async move {
            errors.lock().await.insert(id.clone(), msg.clone());
            let _ = app.emit(
                "tunnel-error",
                serde_json::json!({ "id": id, "error": msg }),
            );
        });
    };

    match counter {
        Some(counter) => tunnels::start_counting(handle, spec, counter, report).await,
        None => tunnels::start(handle, spec, report).await,
    }
    .map_err(|e| format!("{e:#}"))
}

/// As `spawn`, but waiting for a local port we have just released ourselves.
///
/// Only `AddrInUse` is retried: every other bind failure is a real answer, and
/// retrying it would only delay showing it.
async fn spawn_rebinding<R: Runtime>(
    app: &AppHandle<R>,
    handle: Arc<Handle<Client>>,
    errors: Arc<Mutex<HashMap<String, String>>>,
    spec: Tunnel,
    counter: Option<Arc<AtomicU64>>,
) -> Result<RunningTunnel, String> {
    let deadline = Instant::now() + REBIND_PATIENCE;
    loop {
        match spawn(
            app,
            handle.clone(),
            errors.clone(),
            spec.clone(),
            counter.clone(),
        )
        .await
        {
            Ok(running) => return Ok(running),
            Err(e) if e.contains("already in use") && Instant::now() < deadline => {
                tokio::time::sleep(REBIND_INTERVAL).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// What one sweep did, so the caller can log or test it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Sessions rebuilt from scratch because they could no longer carry traffic.
    pub sessions_rebuilt: usize,
    /// Sessions that needed rebuilding and could not be.
    pub sessions_failed: usize,
    /// Individual forwards restarted over a session that was still fine.
    pub tunnels_restarted: usize,
}

/// Check every live session and put right whatever has stopped working, unless
/// the user has turned automatic restoring off.
///
/// Does nothing if a sweep is already running: the timer must never queue up
/// behind a sweep that is waiting out a slow reconnect, or a host that takes
/// twenty seconds to time out would accumulate one pending sweep per tick.
pub async fn sweep<R: Runtime>(app: &AppHandle<R>) -> Swept {
    let state = app.state::<AppState>();
    let Ok(_busy) = state.sweeping.try_lock() else {
        log::debug!("a tunnel sweep is already running; skipping this tick");
        return Swept::default();
    };
    run(app, true, None).await
}

/// As `sweep`, but for one connection the user asked about by hand.
///
/// It runs even when automatic restoring is off — the setting governs the
/// timer, not the button — and it waits for a sweep in flight rather than
/// skipping, so the button always means "the check has been done". It touches
/// only the connection it was asked about: pressing it on one host must not
/// tear down and rebuild another.
pub async fn sweep_now<R: Runtime>(app: &AppHandle<R>, profile_id: &str) -> Swept {
    let state = app.state::<AppState>();
    let _busy = state.sweeping.lock().await;
    run(app, false, Some(profile_id)).await
}

async fn run<R: Runtime>(app: &AppHandle<R>, respect_setting: bool, only: Option<&str>) -> Swept {
    let state = app.state::<AppState>();
    let mut swept = Swept::default();

    // Snapshot the work first. The health probe and any reconnect are network
    // I/O, and holding the one lock the rest of the app shares across them
    // would freeze the UI for as long as a dead host takes to time out.
    let candidates: Vec<(String, Arc<Handle<Client>>, bool)> = {
        let inner = state.inner.lock().await;
        if respect_setting && !inner.settings.auto_restore_tunnels {
            return swept;
        }
        inner
            .sessions
            .iter()
            .filter(|(id, _)| only.is_none_or(|o| o == id.as_str()))
            .map(|(id, live)| {
                (
                    id.clone(),
                    live.session.handle.clone(),
                    // Nothing to do for a session with no forwards the user
                    // wants: a bare session needs no supervision, and probing
                    // it would only add noise to the server's logs.
                    !live.desired.is_empty(),
                )
            })
            .collect()
    };

    for (profile_id, handle, has_work) in candidates {
        if !has_work {
            continue;
        }
        if ssh::healthy(&handle).await {
            recovered(app, &profile_id).await;
            swept.tunnels_restarted += restart_dead_tunnels(app, &profile_id).await;
        } else {
            log::warn!("session {profile_id} can no longer carry a forward; rebuilding");
            match rebuild_session(app, &profile_id).await {
                Ok(true) => swept.sessions_rebuilt += 1,
                Ok(false) => {}
                Err(_) => swept.sessions_failed += 1,
            }
        }
    }

    swept
}

/// The session answered, so undo anything an earlier failed rebuild recorded.
///
/// A rebuild can fail because the network was down at that moment, and then the
/// original session turns out to have survived the blip. Nothing else would
/// ever clear the marks that failure left: the session would stay "dropped",
/// every tunnel would stay red, and the backoff would delay the next real
/// rebuild for a failure that no longer exists.
async fn recovered<R: Runtime>(app: &AppHandle<R>, profile_id: &str) {
    let state = app.state::<AppState>();
    let changed = {
        let mut inner = state.inner.lock().await;
        let Some(live) = inner.sessions.get_mut(profile_id) else {
            return;
        };
        let stale = live.degraded || live.restore_failures > 0 || live.next_restore.is_some();
        live.degraded = false;
        live.restore_failures = 0;
        live.next_restore = None;

        // A forward that is running now is not "could not be restored" any
        // more. Its successful-restore count is kept; one that has never been
        // put back reads green again rather than yellow.
        let mut cleared = false;
        let running: Vec<String> = live
            .tunnels
            .iter()
            .filter(|(_, t)| t.is_alive())
            .map(|(id, _)| id.clone())
            .collect();
        for id in running {
            if let Some(record) = live.restores.get_mut(&id) {
                if record.failed {
                    record.failed = false;
                    record.note = Some(if record.count > 0 {
                        format!(
                            "the connection recovered on its own (rebuilt {}x earlier)",
                            record.count
                        )
                    } else {
                        "the connection recovered on its own".into()
                    });
                    cleared = true;
                }
            }
        }
        stale || cleared
    };
    if changed {
        emit(app, profile_id).await;
    }
}

/// Restart the forwards whose accept loop has finished but which the user still
/// wants, over a session that is otherwise fine.
async fn restart_dead_tunnels<R: Runtime>(app: &AppHandle<R>, profile_id: &str) -> usize {
    let state = app.state::<AppState>();

    // Which ones are dead, and what to rebuild them from.
    let work: Vec<(Tunnel, Option<Arc<AtomicU64>>)> = {
        let inner = state.inner.lock().await;
        let Some(live) = inner.sessions.get(profile_id) else {
            return 0;
        };
        let Some(profile) = inner.profile(profile_id) else {
            return 0;
        };
        profile
            .tunnels
            .iter()
            .filter(|spec| live.desired.contains(&spec.id))
            .filter(|spec| !live.tunnels.get(&spec.id).is_some_and(|t| t.is_alive()))
            .map(|spec| {
                let counter = live.tunnels.get(&spec.id).map(|t| t.connections.clone());
                (spec.clone(), counter)
            })
            .collect()
    };
    if work.is_empty() {
        return 0;
    }

    let mut restarted = 0;
    for (spec, counter) in work {
        // Re-read the session each time: it can close while we are working, and
        // the handle must be the one the session holds now.
        let Some((handle, errors)) = ({
            let mut inner = state.inner.lock().await;
            inner.sessions.get_mut(profile_id).map(|live| {
                // Drop the dead tunnel so its listener is released before we
                // try to bind the same port again.
                if let Some(old) = live.tunnels.remove(&spec.id) {
                    old.stop();
                }
                (live.session.handle.clone(), live.tunnel_errors.clone())
            })
        }) else {
            break;
        };

        let outcome = spawn_rebinding(app, handle, errors, spec.clone(), counter).await;

        let mut inner = state.inner.lock().await;
        let Some(live) = inner.sessions.get_mut(profile_id) else {
            // The session closed under us; abandon the forward we just made
            // rather than leaving an orphan holding a local port.
            if let Ok(running) = outcome {
                running.stop();
            }
            break;
        };
        if !live.desired.contains(&spec.id) {
            // Switched off while we were rebuilding it. The user's choice
            // wins: putting it back would be fighting them over it.
            if let Ok(running) = outcome {
                running.stop();
            }
            continue;
        }
        match outcome {
            Ok(running) => {
                live.tunnels.insert(spec.id.clone(), running);
                live.tunnel_errors.lock().await.remove(&spec.id);
                live.record_restored(&spec.id, "the forward stopped accepting connections");
                restarted += 1;
            }
            Err(e) => {
                live.record_restore_failed(
                    &spec.id,
                    &format!("the forward stopped and could not be restarted: {e}"),
                );
                live.tunnel_errors
                    .lock()
                    .await
                    .insert(spec.id.clone(), e.clone());
            }
        }
    }

    emit(app, profile_id).await;
    restarted
}

/// Build a new SSH session for a profile and put all its wanted forwards back
/// on it.
///
/// Returns `Ok(false)` when nothing was attempted — the session went away, or
/// it is still inside its backoff window after a failure.
async fn rebuild_session<R: Runtime>(app: &AppHandle<R>, profile_id: &str) -> Result<bool, String> {
    let state = app.state::<AppState>();

    let Some((profile, secret, known_hosts, wanted)) = ({
        let inner = state.inner.lock().await;
        let live = inner.sessions.get(profile_id);
        match (live, inner.profile(profile_id)) {
            (Some(live), Some(profile)) => {
                if live.next_restore.is_some_and(|at| Instant::now() < at) {
                    None // still backing off from the last failure
                } else {
                    let wanted: Vec<Tunnel> = profile
                        .tunnels
                        .iter()
                        .filter(|t| live.desired.contains(&t.id))
                        .cloned()
                        .collect();
                    Some((
                        profile.clone(),
                        live.secret.clone(),
                        knownhosts::path_for(&inner.ssh_dir()),
                        wanted,
                    ))
                }
            }
            _ => None,
        }
    }) else {
        return Ok(false);
    };

    // `RequireKnown`: nobody is watching this reconnect, so a host missing from
    // known_hosts is refused rather than trusted — and the stored secret is not
    // handed to it. The first, attended connect already recorded the key.
    let fresh = ssh::connect_profile_with(
        &profile,
        secret.as_deref(),
        &known_hosts,
        ssh::HostKeyPolicy::RequireKnown,
    )
    .await;

    let session = match fresh {
        Ok(session) => session,
        Err(e) => {
            let why = format!("{e:#}");
            let mut inner = state.inner.lock().await;
            if let Some(live) = inner.sessions.get_mut(profile_id) {
                live.restore_failures = live.restore_failures.saturating_add(1);
                live.next_restore = Some(Instant::now() + backoff(live.restore_failures));
                live.degraded = true;
                for spec in &wanted {
                    live.record_restore_failed(
                        &spec.id,
                        &format!("the connection dropped and could not be rebuilt: {why}"),
                    );
                }
            }
            drop(inner);
            emit(app, profile_id).await;
            let _ = app.emit(
                "tunnels-restore-failed",
                serde_json::json!({ "profile_id": profile_id, "error": why }),
            );
            log::warn!("could not rebuild the session for {profile_id}: {why}");
            return Err(why);
        }
    };

    // Swap the dead session for the new one and stop every forward bound to it,
    // keeping the connection counters so the numbers do not go backwards.
    let (handle, errors, counters) = {
        let mut inner = state.inner.lock().await;
        let Some(live) = inner.sessions.get_mut(profile_id) else {
            // Disconnected while we were reconnecting: hang up rather than leak
            // the session we just opened.
            drop(inner);
            ssh::disconnect(&session.handle).await;
            return Ok(false);
        };

        let mut counters = HashMap::new();
        for (id, old) in live.tunnels.drain() {
            counters.insert(id, old.connections.clone());
            old.stop();
        }

        let dead = std::mem::replace(&mut live.session, session);
        live.restore_failures = 0;
        live.next_restore = None;
        live.degraded = false;
        let out = (
            live.session.handle.clone(),
            live.tunnel_errors.clone(),
            counters,
        );
        drop(inner);
        // Best effort on a connection that is already gone; it only matters when
        // the session was half-open rather than truly dead.
        ssh::disconnect(&dead.handle).await;
        out
    };

    reattach_publication(app, profile_id).await;

    let mut back = 0usize;
    let mut total = 0usize;
    for spec in wanted {
        let counter = counters.get(&spec.id).cloned();
        let outcome =
            spawn_rebinding(app, handle.clone(), errors.clone(), spec.clone(), counter).await;

        let mut inner = state.inner.lock().await;
        let Some(live) = inner.sessions.get_mut(profile_id) else {
            if let Ok(running) = outcome {
                running.stop();
            }
            break;
        };
        if !live.desired.contains(&spec.id) {
            // Switched off during the rebuild; leave it off.
            if let Ok(running) = outcome {
                running.stop();
            }
            continue;
        }
        total += 1;
        match outcome {
            Ok(running) => {
                live.tunnels.insert(spec.id.clone(), running);
                live.tunnel_errors.lock().await.remove(&spec.id);
                live.record_restored(&spec.id, "the connection to the server dropped");
                back += 1;
            }
            Err(e) => {
                live.record_restore_failed(
                    &spec.id,
                    &format!("the connection was rebuilt but this forward could not be: {e}"),
                );
                live.tunnel_errors
                    .lock()
                    .await
                    .insert(spec.id.clone(), e.clone());
            }
        }
    }

    emit(app, profile_id).await;
    // Only claim success for forwards that actually came back. When none did,
    // the red lamps already say so, and a success toast would contradict them.
    if back > 0 {
        let _ = app.emit(
            "tunnels-restored",
            serde_json::json!({
                "profile_id": profile_id,
                "name": profile.name,
                "restored": back,
                "total": total,
            }),
        );
    } else if total > 0 {
        let _ = app.emit(
            "tunnels-restore-failed",
            serde_json::json!({
                "profile_id": profile_id,
                "error": "the connection was rebuilt, but none of its tunnels could be",
            }),
        );
    }
    log::info!("rebuilt the session and forwards for {profile_id}");
    Ok(true)
}

/// Carry a published file or folder over to a rebuilt session.
///
/// The server's port belonged to the old session and died with it. Ask the new
/// one for the same port, so a link an agent already holds keeps working, and
/// fall back to any port if the old one is still held. Nothing is done for a
/// publication that was switched off.
async fn reattach_publication<R: Runtime>(app: &AppHandle<R>, profile_id: &str) {
    let state = app.state::<AppState>();
    let Some((handle, slot, shared, previous)) = ({
        let mut inner = state.inner.lock().await;
        inner.sessions.get_mut(profile_id).and_then(|live| {
            let handle = live.session.handle.clone();
            let slot = live.session.publish.clone();
            let publication = live.publication.as_mut()?;
            let previous = publication.remote_port.take()?;
            Some((handle, slot, publication.shared.clone(), previous))
        })
    }) else {
        return;
    };

    if let Ok(mut s) = slot.write() {
        *s = Some(shared);
    }
    let port = match handle.tcpip_forward("127.0.0.1", previous).await {
        Ok(p) => Some(p),
        Err(_) => handle.tcpip_forward("127.0.0.1", 0).await.ok(),
    };
    if port.is_none() {
        if let Ok(mut s) = slot.write() {
            *s = None;
        }
        log::warn!("could not reopen the published link for {profile_id}");
    }

    let mut inner = state.inner.lock().await;
    if let Some(p) = inner
        .sessions
        .get_mut(profile_id)
        .and_then(|l| l.publication.as_mut())
    {
        p.remote_port = port;
    }
    drop(inner);
    let _ = app.emit(
        "publish-changed",
        serde_json::json!({ "profile_id": profile_id }),
    );
}

/// Push one profile's status to the UI.
async fn emit<R: Runtime>(app: &AppHandle<R>, profile_id: &str) {
    let state = app.state::<AppState>();
    let inner = state.inner.lock().await;
    let Some(profile) = inner.profile(profile_id) else {
        return;
    };
    let Some(live) = inner.sessions.get(profile_id) else {
        return;
    };
    let status = live.status(profile).await;
    drop(inner);
    let _ = app.emit("session-status", status);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuthMethod, Profile, RestoreState};
    use crate::state::LiveSession;
    use crate::testserver as harness;
    use tauri::test::{mock_builder, mock_context, noop_assets, MockRuntime};
    use tokio::io::AsyncReadExt;

    /// A connection whose session runs through a proxy the test can blackhole,
    /// while the profile itself points straight at the server — so once the
    /// proxied route is dead, a reconnect has somewhere real to go.
    struct Rig {
        app: tauri::App<MockRuntime>,
        net: harness::Cuttable,
        local: u16,
    }

    const PID: &str = "p1";
    const TID: &str = "t1";

    async fn rig(tag: &str) -> Rig {
        let net = harness::start_cuttable().await;
        let dir =
            std::env::temp_dir().join(format!("easyssh-restore-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let kh = knownhosts::path_for(&dir);

        // Record the server under the address the profile uses, as the user's
        // own first connect would have. The unattended reconnect refuses
        // anything it does not already know.
        let first =
            ssh::connect_password("127.0.0.1", net.upstream, "someone", harness::PASSWORD, &kh)
                .await
                .expect("learn the host key");
        ssh::disconnect(&first.handle).await;

        let local = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let tunnel = Tunnel {
            id: TID.into(),
            name: "Web".into(),
            local_port: local,
            remote_host: "10.0.0.9".into(),
            remote_port: 8443,
            auto_start: true,
            scheme: "http".into(),
        };
        let profile = Profile {
            id: PID.into(),
            name: "Box".into(),
            host: "127.0.0.1".into(),
            port: net.upstream,
            username: "someone".into(),
            auth: AuthMethod::Password,
            key_path: None,
            tunnels: vec![tunnel.clone()],
            last_connected: None,
            color: None,
            key_installed: false,
            from_config: false,
            config_alias: None,
            customized: true,
        };

        // The live session goes through the proxy.
        let session =
            ssh::connect_password("127.0.0.1", net.port, "someone", harness::PASSWORD, &kh)
                .await
                .expect("connect through the proxy");

        let app = mock_builder()
            .manage(AppState::default())
            .build(mock_context(noop_assets()))
            .expect("mock app");
        let handle = app.handle().clone();

        let mut live = LiveSession::new(session, "test".into(), Some(harness::PASSWORD.into()));
        let running = spawn(
            &handle,
            live.session.handle.clone(),
            live.tunnel_errors.clone(),
            tunnel,
            None,
        )
        .await
        .expect("start the forward");
        live.tunnels.insert(TID.into(), running);
        live.desired.insert(TID.into());

        {
            let state = handle.state::<AppState>();
            let mut inner = state.inner.lock().await;
            inner.settings.ssh_dir = Some(dir.display().to_string());
            inner.profiles.push(profile);
            inner.sessions.insert(PID.into(), live);
        }

        Rig { app, net, local }
    }

    /// Read the first line a connection through the forward gets back, or
    /// `None` if nothing arrives — a forward that is silently dead.
    async fn through(local: u16) -> Option<String> {
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", local))
            .await
            .ok()?;
        let mut buf = vec![0u8; 64];
        match tokio::time::timeout(Duration::from_millis(1500), c.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).trim().to_string()),
            _ => None,
        }
    }

    async fn restore_of(app: &tauri::App<MockRuntime>) -> (RestoreState, u32, bool) {
        let state = app.state::<AppState>();
        let inner = state.inner.lock().await;
        let live = inner.sessions.get(PID).expect("session");
        let r = live.restores.get(TID).cloned().unwrap_or_default();
        (r.state(), r.count, live.degraded)
    }

    /// The whole fix, end to end: a forward whose session silently died is
    /// noticed, the session is rebuilt, and the same local port carries traffic
    /// again — with the restore lamp turned yellow to say so.
    #[tokio::test]
    async fn a_silently_dead_forward_is_rebuilt_and_works_again() {
        let rig = rig("rebuild").await;
        assert_eq!(
            through(rig.local).await.as_deref(),
            Some("target=10.0.0.9:8443")
        );
        assert_eq!(
            restore_of(&rig.app).await.0,
            RestoreState::Never,
            "green to begin with"
        );

        rig.net.blackhole();
        assert_eq!(
            through(rig.local).await,
            None,
            "the forward should be dead now"
        );

        let swept = sweep_now(rig.app.handle(), PID).await;
        assert_eq!(swept.sessions_rebuilt, 1, "{swept:?}");

        assert_eq!(
            through(rig.local).await.as_deref(),
            Some("target=10.0.0.9:8443"),
            "the rebuilt forward does not carry traffic"
        );
        let (state, count, degraded) = restore_of(&rig.app).await;
        assert_eq!(state, RestoreState::Restored, "the lamp should be yellow");
        assert_eq!(count, 1);
        assert!(!degraded);
    }

    /// A published link is part of the connection, so it has to survive the
    /// connection being rebuilt: the file is still fetchable afterwards.
    #[tokio::test]
    async fn a_published_link_survives_the_session_being_rebuilt() {
        use tokio::io::AsyncWriteExt;

        let rig = rig("publish").await;
        let file = std::env::temp_dir().join(format!("easyssh-pub-{}.txt", std::process::id()));
        std::fs::write(&file, "still here").unwrap();
        let shared = Arc::new(crate::publish::Shared::new(&file).unwrap());
        {
            let state = rig.app.state::<AppState>();
            let mut inner = state.inner.lock().await;
            let live = inner.sessions.get_mut(PID).unwrap();
            *live.session.publish.write().unwrap() = Some(shared.clone());
            let port = live
                .session
                .handle
                .tcpip_forward("127.0.0.1", 0)
                .await
                .unwrap();
            live.publication = Some(crate::publish::Publication {
                shared: shared.clone(),
                remote_port: Some(port),
                rotator: None,
            });
        }

        rig.net.blackhole();
        let swept = sweep_now(rig.app.handle(), PID).await;
        assert_eq!(swept.sessions_rebuilt, 1, "{swept:?}");

        let port = {
            let state = rig.app.state::<AppState>();
            let inner = state.inner.lock().await;
            inner.sessions[PID]
                .publication
                .as_ref()
                .and_then(|p| p.remote_port)
                .expect("the link should be served again after the rebuild")
        };
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port as u16))
            .await
            .unwrap();
        c.write_all(format!("GET {} HTTP/1.1\r\n\r\n", shared.url_path()).as_bytes())
            .await
            .unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut out))
            .await
            .expect("no answer")
            .unwrap();
        assert!(String::from_utf8_lossy(&out).ends_with("still here"));
    }

    /// Reviewer finding: a rebuild that failed during a network blip left the
    /// session "dropped" and every tunnel red for good, even after the original
    /// session turned out to have survived. A healthy probe must clear that.
    #[tokio::test]
    async fn marks_left_by_a_failed_rebuild_clear_once_the_session_answers() {
        let rig = rig("recover").await;
        {
            let state = rig.app.state::<AppState>();
            let mut inner = state.inner.lock().await;
            let live = inner.sessions.get_mut(PID).unwrap();
            live.degraded = true;
            live.restore_failures = 3;
            live.next_restore = Some(Instant::now() + Duration::from_secs(600));
            live.record_restore_failed(TID, "the connection dropped and could not be rebuilt");
        }
        assert_eq!(restore_of(&rig.app).await.0, RestoreState::Failed);

        sweep_now(rig.app.handle(), PID).await;

        let (state, _, degraded) = restore_of(&rig.app).await;
        assert_eq!(
            state,
            RestoreState::Never,
            "a forward that never needed rebuilding is green"
        );
        assert!(
            !degraded,
            "the session is fine and must not read as dropped"
        );
        let state = rig.app.state::<AppState>();
        let inner = state.inner.lock().await;
        let live = inner.sessions.get(PID).unwrap();
        assert_eq!(live.restore_failures, 0, "the backoff was not reset");
        assert!(live.next_restore.is_none());
    }

    /// A forward the user switched off is not the supervisor's to bring back.
    #[tokio::test]
    async fn a_forward_the_user_switched_off_stays_off() {
        let rig = rig("off").await;
        {
            let state = rig.app.state::<AppState>();
            let mut inner = state.inner.lock().await;
            let live = inner.sessions.get_mut(PID).unwrap();
            live.tunnels.remove(TID).unwrap().stop();
            live.desired.remove(TID);
        }
        rig.net.blackhole();
        sweep_now(rig.app.handle(), PID).await;

        assert_eq!(
            through(rig.local).await,
            None,
            "the forward came back on its own"
        );
        let state = rig.app.state::<AppState>();
        let inner = state.inner.lock().await;
        assert!(!inner.sessions.get(PID).unwrap().tunnels.contains_key(TID));
    }

    /// Reviewer finding: an unattended reconnect must not learn a host key,
    /// and so must not hand the stored password to a host nobody has seen.
    #[tokio::test]
    async fn an_unattended_reconnect_refuses_an_unknown_host() {
        let rig = rig("unknown").await;
        {
            // Forget the host, as a rotated or edited known_hosts would.
            let state = rig.app.state::<AppState>();
            let inner = state.inner.lock().await;
            std::fs::write(knownhosts::path_for(&inner.ssh_dir()), "").unwrap();
        }
        rig.net.blackhole();
        sweep_now(rig.app.handle(), PID).await;

        let (state, _, degraded) = restore_of(&rig.app).await;
        assert_eq!(state, RestoreState::Failed, "the lamp should be red");
        assert!(degraded);
        let state = rig.app.state::<AppState>();
        let inner = state.inner.lock().await;
        let kh = std::fs::read_to_string(knownhosts::path_for(&inner.ssh_dir())).unwrap();
        assert!(
            kh.trim().is_empty(),
            "the reconnect recorded a host key nobody approved"
        );
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert!(backoff(2) > backoff(1));
        assert!(backoff(3) > backoff(2));
        // Capped, so a host that comes back is picked up within minutes rather
        // than never.
        assert_eq!(backoff(9), backoff(4));
        assert!(backoff(9) <= Duration::from_secs(600));
    }
}
