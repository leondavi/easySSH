//! Serializable types shared with the UI.

use serde::{Deserialize, Serialize};

fn default_port() -> u16 {
    22
}

/// How we authenticate to a host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// Interactive password. Never persisted to disk.
    Password,
    /// A private key file on this machine.
    #[default]
    Key,
}

/// A local port that is forwarded to a `host:port` reachable from the remote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub local_port: u16,
    /// Address as seen *from the remote machine*. `localhost` means the remote itself.
    #[serde(default = "default_remote_host")]
    pub remote_host: String,
    pub remote_port: u16,
    /// Start this tunnel as soon as the session connects.
    #[serde(default)]
    pub auto_start: bool,
    /// `http` or `https`; used to build the URL for the "Open" button.
    #[serde(default = "default_scheme")]
    pub scheme: String,
}

fn default_remote_host() -> String {
    "localhost".into()
}

fn default_scheme() -> String {
    "http".into()
}

impl Tunnel {
    pub fn local_url(&self) -> String {
        format!("{}://127.0.0.1:{}", self.scheme, self.local_port)
    }
}

/// A saved connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub auth: AuthMethod,
    /// Absolute path to the private key used when `auth == Key`.
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub tunnels: Vec<Tunnel>,
    /// Unix seconds of the last successful connection.
    #[serde(default)]
    pub last_connected: Option<u64>,
    /// Accent colour swatch shown in the sidebar.
    #[serde(default)]
    pub color: Option<String>,
    /// Set once we have installed our public key in the remote's authorized_keys.
    #[serde(default)]
    pub key_installed: bool,
    /// True for entries derived from an ssh config file. These are rebuilt from
    /// the config on every refresh and are never written to profiles.json; the
    /// first time the user changes or connects to one it becomes theirs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_config: bool,
    /// The `Host` alias this came from. Kept even after the user makes the
    /// connection their own, so we can tell where it originated.
    #[serde(default)]
    pub config_alias: Option<String>,
    /// True once the user has explicitly edited this connection. Merely
    /// connecting does not set it: the ssh config stays the source of truth
    /// for hosts the user has not customised, so deleting a `Host` block
    /// removes the connection here too.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub customized: bool,
}

impl Profile {
    /// `user@host` — what you would type after `ssh`.
    pub fn target(&self) -> String {
        format!("{}@{}", self.username, self.host)
    }
}

/// Live status of one tunnel, pushed to the UI.
#[derive(Debug, Clone, Serialize)]
pub struct TunnelStatus {
    pub id: String,
    pub running: bool,
    pub url: String,
    /// Number of connections proxied since the tunnel started.
    pub connections: u64,
    pub error: Option<String>,
}

/// Live status of one session, pushed to the UI.
#[derive(Debug, Clone, Serialize)]
pub struct SessionStatus {
    pub profile_id: String,
    pub connected: bool,
    /// SHA256 fingerprint of the server host key.
    pub server_fingerprint: Option<String>,
    /// True when this host was not in known_hosts and we have just recorded it.
    pub first_contact: bool,
    pub tunnels: Vec<TunnelStatus>,
}

/// Result of the "connect for the first time and install my key" flow.
#[derive(Debug, Clone, Serialize)]
pub struct SetupResult {
    pub installed: bool,
    /// True when the key was already present in authorized_keys.
    pub already_present: bool,
    pub key_path: String,
    pub public_key: String,
    pub server_fingerprint: String,
    pub remote_message: String,
}

/// A private key discovered on this machine.
#[derive(Debug, Clone, Serialize)]
pub struct KeyInfo {
    pub path: String,
    pub name: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub comment: String,
    pub encrypted: bool,
}

/// A place on this machine where SSH configuration and keys live.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshLocation {
    /// Stable id: the absolute directory path.
    pub id: String,
    /// What the picker shows, e.g. "Personal (~/.ssh)".
    pub label: String,
    pub dir: String,
    /// The `config` file inside `dir`, whether or not it exists yet.
    pub config_path: String,
    pub dir_exists: bool,
    pub config_exists: bool,
    /// How many private keys and `Host` entries we found here.
    pub key_count: usize,
    pub host_count: usize,
    /// True for the conventional per-user location for this OS.
    pub is_default: bool,
    /// `user` or `system`; system locations are read-only for key generation.
    pub scope: String,
}

/// One `Host` block from an ssh config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshHostEntry {
    /// The name you would type after `ssh`.
    pub alias: String,
    pub hostname: String,
    pub user: Option<String>,
    pub port: u16,
    pub identity_file: Option<String>,
    /// The config file this block came from, once Includes are followed.
    pub source: String,
    /// True when easySSH already has a profile for this alias/host.
    pub already_imported: bool,
    /// True when this host can log in without typing a password: an
    /// `IdentityFile` that exists on disk, or a default key ssh would try.
    pub auto_auth: bool,
    /// Why `auto_auth` is what it is, shown next to the host.
    pub auth_note: String,
}

/// User settings that are not tied to one connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// The `.ssh` directory the app is currently focused on. `None` means the default.
    #[serde(default)]
    pub ssh_dir: Option<String>,
    /// Whether hosts read from the user's ssh config are listed alongside the
    /// connections easySSH owns. Off leaves only easySSH's own list.
    #[serde(default = "yes")]
    pub show_config_hosts: bool,
}

/// `serde` needs a function to default a `bool` to true.
fn yes() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            ssh_dir: None,
            show_config_hosts: true,
        }
    }
}

/// One entry in a `known_hosts` file.
#[derive(Debug, Clone, Serialize)]
pub struct KnownHost {
    /// 1-based line number in the file — the handle used to remove it.
    pub line: usize,
    /// Host patterns this entry covers. Empty when the entry is hashed.
    pub hosts: Vec<String>,
    /// True for `HashKnownHosts` entries, whose names cannot be recovered.
    pub hashed: bool,
    /// `cert-authority` or `revoked`, when the line carries a marker.
    pub marker: Option<String>,
    pub algorithm: String,
    pub fingerprint: String,
    pub comment: String,
    /// Names of saved connections that rely on this entry.
    pub used_by: Vec<String>,
    /// False when the line could not be understood; it is still listed so it
    /// can be removed.
    pub parsed: bool,
}

/// Identifies an entry to remove, including the fingerprint the UI showed, so
/// a file edited underneath us cannot cause the wrong line to be deleted.
#[derive(Debug, Clone, Deserialize)]
pub struct KnownHostRef {
    pub line: usize,
    pub fingerprint: String,
}

/// The result of running one command on a connected host.
///
/// Returned in full rather than as a single string: a command that prints
/// nothing is indistinguishable from a command that failed to run unless the
/// exit status comes back with it.
#[derive(Debug, Clone, Serialize)]
pub struct CommandResult {
    pub code: u32,
    pub stdout: String,
    pub stderr: String,
}

/// Result of the background health checks for one connection.
///
/// Every field is optional because "we have not looked yet" is a distinct state
/// from "we looked and the answer is no" — the UI shows them differently.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProbeStatus {
    pub profile_id: String,
    /// Whether the SSH port accepted a TCP connection.
    pub reachable: Option<bool>,
    pub reachable_at: Option<u64>,
    /// Whether the configured key logs in without a password.
    pub key_auth: Option<bool>,
    pub key_auth_at: Option<u64>,
    /// Why `key_auth` is false, or why it could not be determined.
    pub key_auth_note: Option<String>,
}
