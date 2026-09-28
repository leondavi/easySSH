// Keep the console window from appearing behind the UI on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod ezconfig;
mod keys;
mod knownhosts;
mod model;
mod probe;
mod publish;
mod restore;
mod ssh;
mod sshconfig;
mod state;
mod store;
mod terminal;
#[cfg(test)]
mod testserver;
mod transfer;
mod tunnels;

use std::time::{Duration, SystemTime};

use tauri::{AppHandle, Emitter, Manager};

use model::Profile;
use state::AppState;

/// How often the ssh config is checked for edits made outside easySSH.
const CONFIG_POLL: Duration = Duration::from_secs(2);

/// How often every host is tested for reachability. A TCP connect is cheap.
const REACH_POLL: Duration = Duration::from_secs(45);

/// How often we look for keys that are due to be re-tested. The interval
/// between tests for any one host is governed by `probe::backoff`.
const KEY_TICK: Duration = Duration::from_secs(30);

/// Cap on concurrent probes, so a long list of servers does not open a hundred
/// sockets at once.
const PROBE_CONCURRENCY: usize = 8;

/// How often live sessions are checked for forwards that have stopped carrying
/// traffic.
///
/// Frequent enough that a dropped forward is usually back before the user has
/// finished reloading the page, and rare enough that the check — one SSH channel
/// per session — is not itself a load worth worrying about. `restore::backoff`
/// governs how often a session that cannot be rebuilt is retried, so a host that
/// is genuinely down is not handshaked every twenty seconds.
const TUNNEL_TICK: Duration = Duration::from_secs(20);

/// Re-read the ssh config whenever it changes on disk.
///
/// Without this the connection list is only built at startup, so adding or
/// deleting a `Host` block in an editor appears to do nothing until easySSH is
/// restarted. Polling the modification time is enough here — the file is tiny
/// and changes at human speed — and it avoids a platform-specific file-watching
/// dependency.
fn watch_ssh_config(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        // `None` until the first observation, so startup does not count as a change.
        let mut seen: Option<(std::path::PathBuf, Option<SystemTime>)> = None;

        loop {
            tokio::time::sleep(CONFIG_POLL).await;

            let state = app.state::<AppState>();
            let path = {
                let inner = state.inner.lock().await;
                sshconfig::config_path_for(&inner.ssh_dir())
            };
            // A missing file reads as `None`, so creating or deleting the config
            // counts as a change just as editing it does.
            let stamp = std::fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok());

            let changed = matches!(&seen, Some((p, s)) if *p != path || *s != stamp);
            seen = Some((path, stamp));
            if !changed {
                continue;
            }

            {
                let mut inner = state.inner.lock().await;
                inner.sync_config_profiles();
            }
            // One event only: the front end's `ssh-config-changed` handler
            // already reloads the profile list, so also emitting
            // `profiles-changed` would fetch and re-render it twice.
            let _ = app.emit("ssh-config-changed", ());
        }
    });
}

/// Test every host's SSH port and publish the results.
fn watch_reachability(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            let state = app.state::<AppState>();

            // Snapshot first: the probes are network I/O and must not be done
            // while holding the lock the rest of the app needs.
            let targets: Vec<(String, String, u16)> = {
                let inner = state.inner.lock().await;
                inner
                    .profiles
                    .iter()
                    .map(|p| (p.id.clone(), p.host.clone(), p.port))
                    .collect()
            };

            for chunk in targets.chunks(PROBE_CONCURRENCY) {
                let results = probe_batch(chunk).await;
                let mut inner = state.inner.lock().await;
                for (id, up) in results {
                    let record = inner.probes.entry(id.clone()).or_default();
                    record.status.profile_id = id;
                    record.status.reachable = Some(up);
                    record.status.reachable_at = Some(store::now());
                }
            }

            emit_probes(&app).await;
            tokio::time::sleep(REACH_POLL).await;
        }
    });
}

/// Run a batch of reachability checks concurrently.
async fn probe_batch(batch: &[(String, String, u16)]) -> Vec<(String, bool)> {
    let mut handles = Vec::with_capacity(batch.len());
    for (id, host, port) in batch {
        let (id, host, port) = (id.clone(), host.clone(), *port);
        handles.push(tokio::spawn(async move {
            (id, probe::reachable(&host, port).await)
        }));
    }
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(r) = h.await {
            out.push(r);
        }
    }
    out
}

/// Test whether a key logs in without a password, for hosts that are due.
///
/// Covers connections set to use a password too: when a key on this machine
/// already gets in, the connection is switched to it and counts as set up, so
/// the user is never asked to install a key the server already trusts.
///
/// Skipped entirely while a session is open — that connection already proves
/// the answer, and a redundant handshake would only add noise to the server's
/// auth log.
fn watch_key_auth(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(KEY_TICK).await;
            let now = std::time::Instant::now();
            let state = app.state::<AppState>();

            let (due, ssh_dir, known_hosts) = {
                let inner = state.inner.lock().await;
                let ssh_dir = inner.ssh_dir();
                let known_hosts = knownhosts::path_for(&ssh_dir);
                let due: Vec<Profile> = inner
                    .profiles
                    .iter()
                    .filter(|p| !inner.sessions.contains_key(&p.id))
                    .filter(|p| {
                        // Do not waste a handshake on a host we just found down.
                        inner
                            .probes
                            .get(&p.id)
                            .map(|r| r.status.reachable != Some(false))
                            .unwrap_or(true)
                    })
                    .filter(|p| {
                        inner
                            .probes
                            .get(&p.id)
                            .and_then(|r| r.next_key_check)
                            .map(|at| now >= at)
                            .unwrap_or(true)
                    })
                    .cloned()
                    .collect();
                (due, ssh_dir, known_hosts)
            };

            if due.is_empty() {
                continue;
            }

            for profile in due {
                // `RequireKnown`: nobody is watching, so a host that has never
                // been connected to is left for the user to meet first.
                let outcome = probe::key_auth(
                    &profile,
                    &ssh_dir,
                    &known_hosts,
                    ssh::HostKeyPolicy::RequireKnown,
                )
                .await;

                let mut inner = state.inner.lock().await;
                let mut switched = false;
                match outcome {
                    probe::KeyAuth::Works(path) => {
                        switched = inner.record_working_key(&profile.id, &path.to_string_lossy());
                    }
                    probe::KeyAuth::Refused(why) => {
                        let record = inner.probes.entry(profile.id.clone()).or_default();
                        record.status.profile_id = profile.id.clone();
                        record.status.key_auth_at = Some(store::now());
                        record.status.key_auth = Some(false);
                        record.status.key_auth_note = Some(why);
                        record.status.passwordless_key = None;
                        record.failures = record.failures.saturating_add(1);
                    }
                    probe::KeyAuth::Unknown(why) => {
                        let record = inner.probes.entry(profile.id.clone()).or_default();
                        record.status.profile_id = profile.id.clone();
                        record.status.key_auth_at = Some(store::now());
                        record.status.key_auth = None;
                        record.status.key_auth_note = Some(why);
                    }
                }
                if let Some(record) = inner.probes.get_mut(&profile.id) {
                    record.next_key_check =
                        Some(std::time::Instant::now() + probe::backoff(record.failures));
                }
                drop(inner);

                if switched {
                    // Said out loud: the connection's login method just changed
                    // without the user touching it.
                    let _ = app.emit("profiles-changed", ());
                    let _ = app.emit(
                        "passwordless-found",
                        serde_json::json!({ "profile_id": profile.id, "name": profile.name }),
                    );
                }

                // Publish after each host rather than after the whole sweep: on
                // first run every connection is due at once, and a handshake per
                // host would otherwise leave the lamps grey for minutes.
                emit_probes(&app).await;
            }
        }
    });
}

/// Watch the forwards easySSH is running and rebuild the ones that have died.
///
/// This is what stops a tunnel from going quietly useless when the SSH transport
/// underneath it drops: the local listener survives that, so without a check
/// like this one nothing notices until the user does. See `restore` for the
/// details of what is detected and what is done about it.
fn watch_tunnels(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(TUNNEL_TICK).await;
            let swept = restore::sweep(&app).await;
            if swept != restore::Swept::default() {
                log::info!("tunnel sweep: {swept:?}");
            }
        }
    });
}

async fn emit_probes(app: &AppHandle) {
    let state = app.state::<AppState>();
    let all: Vec<model::ProbeStatus> = {
        let inner = state.inner.lock().await;
        inner.probes.values().map(|r| r.status.clone()).collect()
    };
    let _ = app.emit("probe-status", all);
}

/// Load the connections easySSH owns, moving them out of the old
/// `profiles.json` first if this is the first run since that changed.
fn load_connections(settings: &model::Settings) -> Vec<Profile> {
    let dir = state::ssh_dir_for(settings);
    let mut profiles = ezconfig::load(&dir);

    if let Some(legacy) = store::take_legacy_profiles() {
        // Keep whatever is already in ez_config: it is the newer of the two.
        for old in legacy {
            let known = profiles.iter().any(|p| {
                p.host.eq_ignore_ascii_case(&old.host)
                    && p.port == old.port
                    && p.username == old.username
            });
            if !known {
                profiles.push(old);
            }
        }
        if let Err(e) = ezconfig::save(&dir, &profiles) {
            eprintln!(
                "easySSH: could not write {}: {e}",
                ezconfig::path_for(&dir).display()
            );
        }
    }
    profiles
}

fn main() {
    let settings = store::load_settings();
    let profiles = load_connections(&settings);

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::new(profiles, settings))
        .invoke_handler(tauri::generate_handler![
            commands::list_profiles,
            commands::save_profile,
            commands::delete_profile,
            commands::list_keys,
            commands::generate_key,
            commands::use_key_file,
            commands::fix_key_permissions,
            commands::public_key_text,
            commands::connect,
            commands::disconnect,
            commands::session_statuses,
            commands::remote_description,
            commands::setup_key_auth,
            commands::start_tunnel,
            commands::stop_tunnel,
            commands::open_terminal,
            commands::terminal_preview,
            commands::run_command,
            commands::list_ssh_locations,
            commands::set_ssh_location,
            commands::active_ssh_location,
            commands::list_ssh_hosts,
            commands::add_to_ssh_config,
            commands::pick_key_file,
            commands::open_url,
            commands::list_known_hosts,
            commands::remove_known_hosts,
            commands::known_hosts_path,
            commands::probe_statuses,
            commands::app_settings,
            commands::import_ssh_host,
            commands::set_show_config_hosts,
            commands::app_version,
            commands::restore_tunnels,
            commands::detect_passwordless,
            commands::send_path,
            commands::receive_path,
            commands::list_remote_dir,
            commands::default_receive_dir,
            commands::pick_local_path,
            commands::publish_status,
            commands::publish_choose,
            commands::publish_serving,
            commands::publish_new_link,
            commands::publish_clear,
            commands::set_auto_restore_tunnels,
        ])
        .setup(|app| {
            watch_ssh_config(app.handle().clone());
            watch_reachability(app.handle().clone());
            watch_key_auth(app.handle().clone());
            watch_tunnels(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("easySSH failed to start");
}
