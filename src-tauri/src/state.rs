//! Everything the app holds in memory: profiles, live sessions, live tunnels.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::model::{Profile, SessionStatus, Settings, Tunnel, TunnelStatus};
use crate::ssh::Session;
use crate::tunnels::RunningTunnel;

/// One connected host and the forwards running over it.
pub struct LiveSession {
    pub session: Session,
    pub tunnels: HashMap<String, RunningTunnel>,
    /// Errors reported by tunnel tasks after they started, keyed by tunnel id.
    pub tunnel_errors: Arc<Mutex<HashMap<String, String>>>,
    pub remote_description: String,
}

impl LiveSession {
    pub async fn status(&self, profile: &Profile) -> SessionStatus {
        let errors = self.tunnel_errors.lock().await.clone();
        let tunnels = profile
            .tunnels
            .iter()
            .map(|spec| self.tunnel_status(spec, &errors))
            .collect();

        SessionStatus {
            profile_id: profile.id.clone(),
            connected: true,
            server_fingerprint: Some(self.session.fingerprint.clone()),
            first_contact: self.session.first_contact,
            tunnels,
        }
    }

    fn tunnel_status(&self, spec: &Tunnel, errors: &HashMap<String, String>) -> TunnelStatus {
        let running = self.tunnels.get(&spec.id);
        TunnelStatus {
            id: spec.id.clone(),
            running: running.map(|t| t.is_alive()).unwrap_or(false),
            url: spec.local_url(),
            connections: running
                .map(|t| t.connections.load(std::sync::atomic::Ordering::Relaxed))
                .unwrap_or(0),
            error: errors.get(&spec.id).cloned(),
        }
    }
}

#[derive(Default)]
pub struct Inner {
    pub profiles: Vec<Profile>,
    pub sessions: HashMap<String, LiveSession>,
    pub settings: Settings,
}

impl Inner {
    /// The `.ssh` directory the user is focused on, falling back to the
    /// conventional one for this OS.
    pub fn ssh_dir(&self) -> std::path::PathBuf {
        match &self.settings.ssh_dir {
            Some(dir) if !dir.is_empty() => std::path::PathBuf::from(dir),
            _ => crate::keys::default_ssh_dir_path().unwrap_or_default(),
        }
    }

    pub fn profile(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn profile_mut(&mut self, id: &str) -> Option<&mut Profile> {
        self.profiles.iter_mut().find(|p| p.id == id)
    }

    /// Rebuild the connection list's config-derived entries from the focused
    /// `.ssh` directory, so choosing a configuration immediately shows the
    /// servers defined in it.
    ///
    /// A host already covered by a saved profile is left alone — the user's own
    /// settings for it win over what the config file says.
    pub fn sync_config_profiles(&mut self) {
        let dir = self.ssh_dir();
        let defined = crate::sshconfig::parse_config(&crate::sshconfig::config_path_for(&dir))
            .unwrap_or_default();

        // Link a saved connection back to the config when it plainly came from
        // there: same host and port, and nothing the user has added since.
        // Earlier versions copied config hosts into profiles.json as free-
        // standing entries, which then shadowed the config file and could not
        // be removed by deleting their `Host` block.
        for p in &mut self.profiles {
            let untouched = p.config_alias.is_none()
                && !p.customized
                && p.tunnels.is_empty()
                && !p.key_installed;
            if !untouched {
                continue;
            }
            // Require the name to match the alias too. The old import flow
            // named every copy after its `Host` alias, so this identifies them
            // precisely, while a connection the user typed in themselves keeps
            // its own name and is left alone.
            if let Some(host) = defined.iter().find(|h| {
                h.port == p.port && h.hostname.eq_ignore_ascii_case(&p.host) && h.alias == p.name
            }) {
                p.config_alias = Some(host.alias.clone());
            }
        }

        // An entry that came from a config file and was never explicitly edited
        // is not the user's own, however it ended up in profiles.json. Treating
        // it as derived here means it tracks the config — including vanishing
        // when its `Host` block is deleted.
        for p in &mut self.profiles {
            if p.config_alias.is_some() && !p.customized {
                p.from_config = true;
            }
        }

        // Anything still connected must survive, or we would orphan its session.
        self.profiles
            .retain(|p| !p.from_config || self.sessions.contains_key(&p.id));

        let owned: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| !p.from_config)
            .cloned()
            .collect();
        let Ok(hosts) = crate::sshconfig::hosts_for(&dir, &owned) else {
            return;
        };

        for host in hosts {
            if host.already_imported {
                continue;
            }
            let id = derived_id(&dir.display().to_string(), &host.alias);
            if self.profiles.iter().any(|p| p.id == id) {
                continue; // already present and connected
            }

            // A host with a key configured locally can go straight to key auth.
            let auth = if host.auto_auth && host.identity_file.is_some() {
                crate::model::AuthMethod::Key
            } else {
                crate::model::AuthMethod::Password
            };

            self.profiles.push(Profile {
                id,
                name: host.alias.clone(),
                host: host.hostname.clone(),
                port: host.port,
                username: host.user.clone().unwrap_or_else(local_user),
                auth,
                key_path: host.identity_file.clone(),
                tunnels: Vec::new(),
                last_connected: None,
                color: None,
                key_installed: false,
                from_config: true,
                config_alias: Some(host.alias),
                customized: false,
            });
        }
    }

    /// Mark a connection as the user's own, so it persists independently of
    /// the ssh config. Only an explicit edit does this — see `customized`.
    pub fn adopt(&mut self, id: &str) {
        if let Some(p) = self.profile_mut(id) {
            p.from_config = false;
            p.customized = true;
        }
    }
}

/// Stable across refreshes, so the selected row does not jump when the list
/// is rebuilt.
fn derived_id(dir: &str, alias: &str) -> String {
    format!("config:{dir}:{alias}")
}

/// The local account name, used when a config Host block names no User.
fn local_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".into())
}

/// Tauri managed state. A single lock keeps profile edits and session
/// bookkeeping from racing each other.
#[derive(Default)]
pub struct AppState {
    pub inner: Mutex<Inner>,
}

impl AppState {
    pub fn new(profiles: Vec<Profile>, settings: Settings) -> Self {
        let mut inner = Inner {
            profiles,
            sessions: HashMap::new(),
            settings,
        };
        // Populate the config-derived connections before the window opens, so
        // the sidebar is already complete on first paint.
        inner.sync_config_profiles();
        Self {
            inner: Mutex::new(inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuthMethod, Settings};

    fn config_dir(tag: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("easyssh-state-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config"), body).unwrap();
        dir
    }

    fn inner_for(dir: &std::path::Path, profiles: Vec<Profile>) -> Inner {
        Inner {
            profiles,
            sessions: HashMap::new(),
            settings: Settings {
                ssh_dir: Some(dir.display().to_string()),
            },
        }
    }

    fn saved(name: &str, host: &str, port: u16) -> Profile {
        Profile {
            id: format!("saved-{name}"),
            name: name.into(),
            host: host.into(),
            port,
            username: "me".into(),
            auth: AuthMethod::Password,
            key_path: None,
            tunnels: Vec::new(),
            last_connected: None,
            color: None,
            key_installed: false,
            from_config: false,
            config_alias: None,
            customized: false,
        }
    }

    #[test]
    fn config_hosts_become_connections() {
        let dir = config_dir(
            "basic",
            "Host web\n  HostName 10.0.0.5\n  User deploy\n  Port 2222\n",
        );
        let mut inner = inner_for(&dir, Vec::new());
        inner.sync_config_profiles();

        assert_eq!(inner.profiles.len(), 1);
        let p = &inner.profiles[0];
        assert_eq!(p.host, "10.0.0.5");
        assert_eq!(p.username, "deploy");
        assert_eq!(p.port, 2222);
        assert!(p.from_config);
        assert_eq!(p.config_alias.as_deref(), Some("web"));
    }

    #[test]
    fn a_differently_named_connection_to_a_config_host_is_left_alone() {
        // Same host as a config block but the user's own name for it: not an
        // import copy, so it keeps its identity rather than being relinked.
        let dir = config_dir("named", "Host web\n  HostName 10.0.0.5\n");
        let mut inner = inner_for(&dir, vec![saved("My box", "10.0.0.5", 22)]);
        inner.sync_config_profiles();

        let kept = inner
            .profiles
            .iter()
            .find(|p| !p.from_config)
            .expect("kept");
        assert_eq!(kept.name, "My box");
        assert!(kept.config_alias.is_none());
    }

    #[test]
    fn a_saved_profile_wins_over_the_same_config_host() {
        let dir = config_dir("dedupe", "Host web\n  HostName 10.0.0.5\n  User deploy\n");
        let mut inner = inner_for(&dir, vec![saved("Mine", "10.0.0.5", 22)]);
        inner.sync_config_profiles();

        // One entry, and it is the user's — not a duplicate from the config.
        assert_eq!(inner.profiles.len(), 1);
        assert_eq!(inner.profiles[0].name, "Mine");
        assert!(!inner.profiles[0].from_config);
    }

    #[test]
    fn refreshing_is_stable_and_does_not_accumulate() {
        let dir = config_dir(
            "stable",
            "Host a\n  HostName a.example\nHost b\n  HostName b.example\n",
        );
        let mut inner = inner_for(&dir, Vec::new());
        inner.sync_config_profiles();
        let first: Vec<String> = inner.profiles.iter().map(|p| p.id.clone()).collect();

        inner.sync_config_profiles();
        let second: Vec<String> = inner.profiles.iter().map(|p| p.id.clone()).collect();

        assert_eq!(inner.profiles.len(), 2);
        // Ids must be stable, or the selected row would jump on every refresh.
        assert_eq!(first, second);
    }

    #[test]
    fn adopting_makes_an_entry_the_users_own() {
        let dir = config_dir("adopt", "Host web\n  HostName 10.0.0.5\n");
        let mut inner = inner_for(&dir, Vec::new());
        inner.sync_config_profiles();
        let id = inner.profiles[0].id.clone();

        inner.adopt(&id);
        assert!(!inner.profiles[0].from_config);

        // Once adopted it survives a refresh rather than being rebuilt.
        inner.sync_config_profiles();
        assert_eq!(inner.profiles.len(), 1);
        assert!(!inner.profiles[0].from_config);
    }

    #[test]
    fn switching_location_replaces_the_derived_entries() {
        let a = config_dir("switch-a", "Host alpha\n  HostName alpha.example\n");
        let b = config_dir("switch-b", "Host beta\n  HostName beta.example\n");

        let mut inner = inner_for(&a, vec![saved("Mine", "mine.example", 22)]);
        inner.sync_config_profiles();
        assert!(inner.profiles.iter().any(|p| p.host == "alpha.example"));

        inner.settings.ssh_dir = Some(b.display().to_string());
        inner.sync_config_profiles();

        // The previous location's hosts must be gone, not merged in.
        assert!(!inner.profiles.iter().any(|p| p.host == "alpha.example"));
        assert!(inner.profiles.iter().any(|p| p.host == "beta.example"));
        assert!(inner.profiles.iter().any(|p| p.host == "mine.example"));
        assert_eq!(inner.profiles.len(), 2);
    }

    #[test]
    fn a_location_with_no_hosts_clears_the_derived_entries() {
        let a = config_dir("empty-a", "Host alpha\n  HostName alpha.example\n");
        // A config with only a wildcard block defines no connectable host —
        // this is what /etc/ssh/ssh_config normally looks like.
        let empty = config_dir("empty-b", "Host *\n  ServerAliveInterval 60\n");

        let mut inner = inner_for(&a, vec![saved("Mine", "mine.example", 22)]);
        inner.sync_config_profiles();
        assert_eq!(inner.profiles.len(), 2);

        inner.settings.ssh_dir = Some(empty.display().to_string());
        inner.sync_config_profiles();
        assert_eq!(inner.profiles.len(), 1);
        assert_eq!(inner.profiles[0].name, "Mine");
    }

    #[test]
    fn a_missing_directory_is_a_valid_selection() {
        let a = config_dir("missing-a", "Host alpha\n  HostName alpha.example\n");
        let mut inner = inner_for(&a, Vec::new());
        inner.sync_config_profiles();
        assert_eq!(inner.profiles.len(), 1);

        inner.settings.ssh_dir = Some("/nonexistent/easyssh/path".into());
        inner.sync_config_profiles();
        assert!(inner.profiles.is_empty());
    }

    #[test]
    fn deleting_a_host_from_the_config_removes_the_connection() {
        let dir = config_dir(
            "deleted",
            "Host web\n  HostName 10.0.0.5\nHost db\n  HostName db.internal\n",
        );
        let mut inner = inner_for(&dir, Vec::new());
        inner.sync_config_profiles();
        assert_eq!(inner.profiles.len(), 2);

        // Connecting must not take ownership, or the entry would outlive its
        // Host block. Simulate what `connect` does: record the time only.
        let id = inner.profiles[0].id.clone();
        inner.profile_mut(&id).unwrap().last_connected = Some(1);

        // The user removes `web` from the config file.
        std::fs::write(dir.join("config"), "Host db\n  HostName db.internal\n").unwrap();
        inner.sync_config_profiles();

        let hosts: Vec<&str> = inner.profiles.iter().map(|p| p.host.as_str()).collect();
        assert_eq!(
            hosts,
            vec!["db.internal"],
            "the deleted host is still listed"
        );
    }

    #[test]
    fn a_connection_the_user_edited_survives_config_deletion() {
        let dir = config_dir("edited", "Host web\n  HostName 10.0.0.5\n");
        let mut inner = inner_for(&dir, Vec::new());
        inner.sync_config_profiles();
        let id = inner.profiles[0].id.clone();

        // An explicit edit makes it theirs; their work should not evaporate.
        inner.adopt(&id);
        assert!(inner.profiles[0].customized);

        std::fs::write(dir.join("config"), "").unwrap();
        inner.sync_config_profiles();

        assert_eq!(inner.profiles.len(), 1);
        assert_eq!(inner.profiles[0].host, "10.0.0.5");
    }

    #[test]
    fn repairs_hosts_persisted_by_an_earlier_version() {
        // An older build saved a config host into profiles.json as soon as you
        // connected. Such an entry is owned but never customised, and it must
        // start tracking the config again rather than linger forever.
        let dir = config_dir("legacy", "Host db\n  HostName db.internal\n");
        let stale = Profile {
            id: "config:old:web".into(),
            name: "web".into(),
            host: "10.0.0.5".into(),
            port: 22,
            username: "deploy".into(),
            auth: AuthMethod::Key,
            key_path: None,
            tunnels: Vec::new(),
            last_connected: Some(1),
            color: None,
            key_installed: false,
            from_config: false, // persisted as "owned"
            config_alias: Some("web".into()),
            customized: false, // but never actually edited
        };
        let mut inner = inner_for(&dir, vec![stale]);
        inner.sync_config_profiles();

        let hosts: Vec<&str> = inner.profiles.iter().map(|p| p.host.as_str()).collect();
        assert_eq!(
            hosts,
            vec!["db.internal"],
            "the stale entry was not cleaned up"
        );
    }

    #[test]
    fn relinks_copies_made_by_the_old_import_flow() {
        // The removed "import from config" feature wrote free-standing copies
        // with no link back to the config. They shadowed the real Host block
        // and survived its deletion, which is the bug this repairs.
        let dir = config_dir(
            "relink",
            "Host Jet1\n  HostName 192.168.0.228\n  User david\n",
        );
        let mut imported = saved("Jet1", "192.168.0.228", 22);
        imported.config_alias = None;
        imported.customized = false;

        let mut inner = inner_for(&dir, vec![imported]);
        inner.sync_config_profiles();

        // It is now the config's entry, not an independent copy.
        assert_eq!(
            inner.profiles.len(),
            1,
            "the copy and the config host both appeared"
        );
        assert!(inner.profiles[0].from_config);
        assert_eq!(inner.profiles[0].config_alias.as_deref(), Some("Jet1"));

        // Deleting the Host block now removes it, as the user expects.
        std::fs::write(dir.join("config"), "").unwrap();
        inner.sync_config_profiles();
        assert!(inner.profiles.is_empty());
    }

    #[test]
    fn a_copy_the_user_invested_in_is_not_relinked() {
        // Same host as a config block, but carrying the user's own tunnel:
        // silently replacing it with the config's version would lose work.
        let dir = config_dir("invested", "Host Jet1\n  HostName 192.168.0.228\n");
        let mut owned = saved("Jet1", "192.168.0.228", 22);
        owned.tunnels.push(crate::model::Tunnel {
            id: "t1".into(),
            name: "Web".into(),
            local_port: 8080,
            remote_host: "localhost".into(),
            remote_port: 3000,
            auto_start: false,
            scheme: "http".into(),
        });

        let mut inner = inner_for(&dir, vec![owned]);
        inner.sync_config_profiles();

        let kept = inner
            .profiles
            .iter()
            .find(|p| !p.from_config)
            .expect("kept");
        assert_eq!(kept.tunnels.len(), 1);
        assert!(kept.config_alias.is_none());
    }

    #[test]
    fn an_orphaned_copy_of_a_deleted_host_stays_put() {
        // Nothing in the config matches it any more, so easySSH cannot know it
        // ever came from there. Deleting it is the user's call, not ours.
        let dir = config_dir("orphan", "Host other\n  HostName 10.0.0.9\n");
        let orphan = saved("cells-models-serv", "35.188.133.141", 22);

        let mut inner = inner_for(&dir, vec![orphan]);
        inner.sync_config_profiles();

        assert!(inner
            .profiles
            .iter()
            .any(|p| p.host == "35.188.133.141" && !p.from_config));
    }

    #[test]
    fn a_hand_made_connection_is_never_touched_by_the_config() {
        let dir = config_dir("handmade", "Host web\n  HostName 10.0.0.5\n");
        // No config_alias: the user typed this one in themselves.
        let mut inner = inner_for(&dir, vec![saved("Mine", "mine.example", 22)]);
        inner.sync_config_profiles();

        std::fs::write(dir.join("config"), "").unwrap();
        inner.sync_config_profiles();

        assert_eq!(inner.profiles.len(), 1);
        assert_eq!(inner.profiles[0].name, "Mine");
    }

    #[test]
    fn derived_entries_are_not_written_to_disk() {
        let dir = config_dir("persist", "Host web\n  HostName 10.0.0.5\n");
        let mut inner = inner_for(&dir, vec![saved("Mine", "other.example", 22)]);
        inner.sync_config_profiles();
        assert_eq!(inner.profiles.len(), 2);

        let json = serde_json::to_string(
            &inner
                .profiles
                .iter()
                .filter(|p| !p.from_config)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(json.contains("other.example"));
        assert!(!json.contains("10.0.0.5"));
    }
}
