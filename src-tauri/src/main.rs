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

use state::AppState;

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
        .run(tauri::generate_context!())
        .expect("easySSH failed to start");
}
