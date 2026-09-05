// Keep the console window from appearing behind the UI on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod ezconfig;
mod keys;
mod knownhosts;
mod model;
mod probe;
mod ssh;
mod sshconfig;
mod state;
mod store;
mod terminal;
#[cfg(test)]
mod testserver;
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

/// Test whether the configured key still logs in, for hosts that are due.
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

            let (due, known_hosts) = {
                let inner = state.inner.lock().await;
                let known_hosts = knownhosts::path_for(&inner.ssh_dir());
                let due: Vec<Profile> = inner
                    .profiles
                    .iter()
                    .filter(|p| p.auth == model::AuthMethod::Key && p.key_path.is_some())
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
                (due, known_hosts)
            };

            if due.is_empty() {
                continue;
            }

            for profile in due {
                let outcome = probe::key_auth(&profile, &known_hosts).await;

                let mut inner = state.inner.lock().await;
                let record = inner.probes.entry(profile.id.clone()).or_default();
                record.status.profile_id = profile.id.clone();
                record.status.key_auth_at = Some(store::now());

                match outcome {
                    probe::KeyAuth::Works => {
                        record.status.key_auth = Some(true);
                        record.status.key_auth_note = None;
                        record.failures = 0;
                    }
                    probe::KeyAuth::Refused(why) => {
                        record.status.key_auth = Some(false);
                        record.status.key_auth_note = Some(why);
                        record.failures = record.failures.saturating_add(1);
                    }
                    probe::KeyAuth::Unknown(why) => {
                        record.status.key_auth = None;
                        record.status.key_auth_note = Some(why);
                    }
                }
                record.next_key_check =
                    Some(std::time::Instant::now() + probe::backoff(record.failures));
                drop(inner);

                // Publish after each host rather than after the whole sweep: on
                // first run every connection is due at once, and a handshake per
                // host would otherwise leave the lamps grey for minutes.
                emit_probes(&app).await;
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
            commands::inspect_key,
            commands::import_key_file,
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
        ])
        .setup(|app| {
            watch_ssh_config(app.handle().clone());
            watch_reachability(app.handle().clone());
            watch_key_auth(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("easySSH failed to start");
}
