// Keep the console window from appearing behind the UI on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod keys;
mod knownhosts;
mod model;
mod ssh;
mod sshconfig;
mod state;
mod store;
mod terminal;
mod tunnels;

use std::time::{Duration, SystemTime};

use tauri::{AppHandle, Emitter, Manager};

use state::AppState;

/// How often the ssh config is checked for edits made outside easySSH.
const CONFIG_POLL: Duration = Duration::from_secs(2);

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

fn main() {
    let profiles = store::load_profiles().unwrap_or_else(|e| {
        eprintln!("easySSH: could not read saved connections: {e}");
        Vec::new()
    });

    let settings = store::load_settings();

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
        ])
        .setup(|app| {
            watch_ssh_config(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("easySSH failed to start");
}
