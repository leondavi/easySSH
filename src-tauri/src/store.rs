//! On-disk persistence for the app's own settings, and the one-time move of
//! saved connections out of the application data directory into `ez_config`.
//! Passwords are never written anywhere.

use std::fs;
use std::io;
use std::path::PathBuf;

use crate::model::{Profile, Settings};

/// `~/Library/Application Support/easySSH` on macOS, `%APPDATA%\easySSH` on Windows.
pub fn app_dir() -> io::Result<PathBuf> {
    let dir = dirs::config_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no config directory"))?
        .join("easySSH");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn profiles_path() -> io::Result<PathBuf> {
    Ok(app_dir()?.join("profiles.json"))
}

/// Read the connections saved by versions that kept them in the application
/// data directory, and remove that file.
///
/// Connections now live in `ez_config` inside the `.ssh` directory, next to
/// the keys and the config they belong with. Returning `None` once the file is
/// gone is what makes this run exactly once.
pub fn take_legacy_profiles() -> Option<Vec<Profile>> {
    let path = profiles_path().ok()?;
    let raw = fs::read_to_string(&path).ok()?;
    let profiles: Vec<Profile> = serde_json::from_str(&raw).unwrap_or_else(|e| {
        log::warn!("the old profiles.json could not be read ({e}); it will be left in place");
        Vec::new()
    });
    if profiles.is_empty() && !raw.trim().is_empty() && raw.trim() != "[]" {
        return None; // unreadable: keep it rather than throw the user's list away
    }
    let _ = fs::remove_file(&path);
    Some(profiles)
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn settings_path() -> io::Result<PathBuf> {
    Ok(app_dir()?.join("settings.json"))
}

pub fn load_settings() -> Settings {
    let Ok(path) = settings_path() else {
        return Settings::default();
    };
    fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

pub fn save_settings(settings: &Settings) -> io::Result<()> {
    let path = settings_path()?;
    let body = serde_json::to_string_pretty(settings)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, body)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}
