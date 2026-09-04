//! On-disk persistence for profiles. Passwords are never written here.

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

pub fn load_profiles() -> io::Result<Vec<Profile>> {
    let path = profiles_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path)?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    // A profile we cannot parse should not take the whole list down with it.
    match serde_json::from_str(&raw) {
        Ok(profiles) => Ok(profiles),
        Err(e) => {
            log::warn!("profiles.json is not readable ({e}); starting from an empty list");
            Ok(Vec::new())
        }
    }
}

pub fn save_profiles(profiles: &[Profile]) -> io::Result<()> {
    let path = profiles_path()?;
    // Config-derived entries are rebuilt from the ssh config each time, so
    // writing them here would create a stale duplicate of the real source.
    let owned: Vec<&Profile> = profiles.iter().filter(|p| !p.from_config).collect();
    let body = serde_json::to_string_pretty(&owned)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // Write-then-rename so a crash mid-write cannot truncate the existing file.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, body)?;
    fs::rename(&tmp, &path)?;
    Ok(())
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
