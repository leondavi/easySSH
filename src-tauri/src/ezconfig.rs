//! easySSH's own connection store, kept beside the user's SSH material.
//!
//! Connections easySSH owns are written to `<ssh dir>/ez_config`, a real
//! OpenSSH config file pulled into the user's `config` by a single
//! `Include ez_config` line. That keeps the two apart — easySSH never rewrites
//! the file the user maintains by hand — while still making every connection
//! usable as plain `ssh <alias>` from any terminal.
//!
//! The handful of things OpenSSH has no directive for (our profile id, the
//! colour swatch, whether we installed the key, tunnel names and schemes) live
//! in a sidecar `ez_config.json` next to it, keyed by alias.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model::{AuthMethod, Profile, Tunnel};

/// The managed config file's name. Also used to keep it out of the host list
/// parsed from the user's own config, which `Include`s it.
pub const FILE_NAME: &str = "ez_config";

pub fn path_for(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

pub fn meta_path_for(dir: &Path) -> PathBuf {
    dir.join("ez_config.json")
}

/// Is this the file easySSH manages? Compared by name so an `Include` written
/// as `ez_config`, `~/.ssh/ez_config` or an absolute path all match.
pub fn is_managed(path: &Path) -> bool {
    path.file_name().map(|n| n == FILE_NAME).unwrap_or(false)
}

// ───────────────────────────────────────────────────────────── sidecar

/// Everything about a connection that an ssh config cannot express.
#[derive(Serialize, Deserialize, Clone)]
struct Meta {
    alias: String,
    id: String,
    name: String,
    #[serde(default)]
    auth: AuthMethod,
    #[serde(default)]
    color: Option<String>,
    #[serde(default)]
    key_installed: bool,
    #[serde(default)]
    last_connected: Option<u64>,
    #[serde(default)]
    config_alias: Option<String>,
    /// Tunnels, with the names, schemes and auto-start flags that the
    /// `LocalForward` lines in `ez_config` cannot carry.
    #[serde(default)]
    tunnels: Vec<Tunnel>,
}

fn load_meta(dir: &Path) -> Vec<Meta> {
    let Ok(raw) = fs::read_to_string(meta_path_for(dir)) else {
        return Vec::new();
    };
    serde_json::from_str(&raw).unwrap_or_else(|e| {
        log::warn!("ez_config.json is not readable ({e}); falling back to the config file alone");
        Vec::new()
    })
}

// ───────────────────────────────────────────────────────────── reading

/// One `Host` block as written to `ez_config`.
#[derive(Default)]
struct Entry {
    alias: String,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    forwards: Vec<(u16, String, u16)>,
}

/// Parse the managed file. Deliberately its own small parser rather than the
/// general one in `sshconfig`: this file is ours, and we need the
/// `LocalForward` lines that the profile list does not otherwise care about.
fn parse(path: &Path) -> Vec<Entry> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out: Vec<Entry> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `Keyword value` and `Keyword=value` are both valid ssh config.
        let mut parts = line.splitn(2, |c: char| c.is_whitespace() || c == '=');
        let key = parts.next().unwrap_or("").to_ascii_lowercase();
        let value = parts
            .next()
            .unwrap_or("")
            .trim()
            .trim_start_matches('=')
            .trim();
        if value.is_empty() {
            continue;
        }

        if key == "host" {
            // A pattern list is not something easySSH writes; take the first
            // word so a hand-edited block still resolves to one connection.
            out.push(Entry {
                alias: value.split_whitespace().next().unwrap_or("").to_string(),
                ..Default::default()
            });
            continue;
        }
        let Some(entry) = out.last_mut() else {
            continue;
        };
        match key.as_str() {
            "hostname" => entry.hostname = Some(value.to_string()),
            "user" => entry.user = Some(value.to_string()),
            "port" => entry.port = value.parse().ok(),
            "identityfile" if entry.identity_file.is_none() => {
                entry.identity_file = Some(value.trim_matches('"').to_string());
            }
            "localforward" => {
                if let Some(f) = parse_forward(value) {
                    entry.forwards.push(f);
                }
            }
            _ => {}
        }
    }
    out.retain(|e| !e.alias.is_empty());
    out
}

/// `LocalForward [bind:]port host:hostport`, the two forms OpenSSH accepts.
fn parse_forward(value: &str) -> Option<(u16, String, u16)> {
    let mut words = value.split_whitespace();
    let local = words.next()?;
    let remote = words.next()?;

    // The local side may carry a bind address we always write as 127.0.0.1.
    let local_port: u16 = local.rsplit(':').next()?.parse().ok()?;
    let (host, port) = remote.rsplit_once(':')?;
    Some((local_port, host.to_string(), port.parse().ok()?))
}

/// The `Host` aliases easySSH has taken in this directory. ssh resolves them
/// from the same namespace as the user's own config, so nothing else may
/// reuse one.
pub fn aliases(dir: &Path) -> Vec<String> {
    parse(&path_for(dir)).into_iter().map(|e| e.alias).collect()
}

/// Every connection easySSH owns in this `.ssh` directory.
pub fn load(dir: &Path) -> Vec<Profile> {
    let metas = load_meta(dir);
    let entries = parse(&path_for(dir));

    entries
        .into_iter()
        .map(|e| {
            let meta = metas.iter().find(|m| m.alias == e.alias);
            let host = e.hostname.unwrap_or_else(|| e.alias.clone());
            let key_path = e.identity_file;
            // A block edited by hand can name a key where the sidecar said
            // password, and the file on disk is the one ssh would obey.
            let auth = match meta.map(|m| m.auth) {
                Some(a) if key_path.is_some() || a == AuthMethod::Password => a,
                _ if key_path.is_some() => AuthMethod::Key,
                _ => AuthMethod::Password,
            };

            Profile {
                id: meta
                    .map(|m| m.id.clone())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                name: meta
                    .map(|m| m.name.clone())
                    .unwrap_or_else(|| e.alias.clone()),
                host,
                port: e.port.unwrap_or(22),
                username: e.user.unwrap_or_else(local_user),
                auth,
                key_path,
                tunnels: tunnels_for(meta, &e.forwards),
                last_connected: meta.and_then(|m| m.last_connected),
                color: meta.and_then(|m| m.color.clone()),
                key_installed: meta.map(|m| m.key_installed).unwrap_or(false),
                from_config: false,
                config_alias: meta.and_then(|m| m.config_alias.clone()),
                // Everything in this file is the user's own by definition:
                // it only gets here because they saved or imported it.
                customized: true,
            }
        })
        .collect()
}

/// Match the sidecar's tunnels to the `LocalForward` lines actually in the
/// file, so a forward added there by hand shows up in the app rather than
/// being silently dropped the next time we write.
fn tunnels_for(meta: Option<&Meta>, forwards: &[(u16, String, u16)]) -> Vec<Tunnel> {
    let known: Vec<Tunnel> = meta.map(|m| m.tunnels.clone()).unwrap_or_default();
    let mut out: Vec<Tunnel> = known
        .iter()
        .filter(|t| {
            forwards.iter().any(|(lp, h, rp)| {
                *lp == t.local_port && *rp == t.remote_port && h == &t.remote_host
            })
        })
        .cloned()
        .collect();

    for (lp, host, rp) in forwards {
        if out.iter().any(|t| t.local_port == *lp) {
            continue;
        }
        out.push(Tunnel {
            id: uuid::Uuid::new_v4().to_string(),
            name: format!("Port {lp}"),
            local_port: *lp,
            remote_host: host.clone(),
            remote_port: *rp,
            auto_start: true,
            scheme: "http".into(),
        });
    }
    out
}

fn local_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".into())
}

// ───────────────────────────────────────────────────────────── writing

/// Write every owned connection to `ez_config` and its sidecar, and make sure
/// the user's config pulls the file in.
///
/// Config-derived entries are left out: they are rebuilt from the user's own
/// config each time, and copying them here would shadow the file they came
/// from — deleting their `Host` block would no longer remove them.
pub fn save(dir: &Path, profiles: &[Profile]) -> io::Result<()> {
    let owned: Vec<&Profile> = profiles.iter().filter(|p| !p.from_config).collect();

    let mut used: HashSet<String> = HashSet::new();
    let mut body = String::from(
        "# easySSH connections.\n\
         #\n\
         # Written by easySSH and included from your ssh config. Your own\n\
         # config file is never modified beyond that one Include line, and\n\
         # anything you add here by hand is read back — but easySSH rewrites\n\
         # this file whenever a connection changes, so comments and layout\n\
         # will not survive.\n",
    );
    let mut metas: Vec<Meta> = Vec::new();

    for p in &owned {
        let alias = unique_alias(p, &mut used);

        body.push_str(&format!("\nHost {alias}\n"));
        body.push_str(&format!("    HostName {}\n", p.host));
        body.push_str(&format!("    User {}\n", p.username));
        if p.port != 22 {
            body.push_str(&format!("    Port {}\n", p.port));
        }
        if p.auth == AuthMethod::Key {
            if let Some(key) = &p.key_path {
                body.push_str(&format!("    IdentityFile {key}\n"));
                // Without this ssh offers every agent key first and can hit
                // MaxAuthTries before it ever gets to this one.
                body.push_str("    IdentitiesOnly yes\n");
            }
        }
        for t in &p.tunnels {
            body.push_str(&format!(
                "    LocalForward 127.0.0.1:{} {}:{}\n",
                t.local_port, t.remote_host, t.remote_port
            ));
        }

        metas.push(Meta {
            alias,
            id: p.id.clone(),
            name: p.name.clone(),
            auth: p.auth,
            color: p.color.clone(),
            key_installed: p.key_installed,
            last_connected: p.last_connected,
            config_alias: p.config_alias.clone(),
            tunnels: p.tunnels.clone(),
        });
    }

    crate::keys::ensure_dir(dir).map_err(|e| io::Error::other(e.to_string()))?;
    write_private(&path_for(dir), &body)?;
    let json = serde_json::to_string_pretty(&metas)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_private(&meta_path_for(dir), &json)?;
    ensure_include(dir)?;
    Ok(())
}

/// Write-then-rename so a crash mid-write cannot truncate what is there, and
/// keep the result 0600 like the rest of `~/.ssh`.
fn write_private(path: &Path, body: &str) -> io::Result<()> {
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&tmp, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path)
}

/// Add `Include ez_config` to the user's config unless it is already there.
///
/// It goes at the very top: an `Include` inside a `Host` block would only
/// apply to that host, and OpenSSH takes the first value it sees for each
/// directive, so an easySSH connection must be able to state its own.
pub fn ensure_include(dir: &Path) -> io::Result<()> {
    let path = crate::sshconfig::config_path_for(dir);
    let existing = fs::read_to_string(&path).unwrap_or_default();

    let present = existing.lines().any(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return false;
        }
        let mut words = line.split_whitespace();
        words.next().map(|w| w.eq_ignore_ascii_case("include")) == Some(true)
            && words.any(|w| is_managed(Path::new(w.trim_matches('"'))))
    });
    if present {
        return Ok(());
    }

    let body = format!(
        "# easySSH keeps its own connections in {FILE_NAME}, beside this file.\n\
         Include {FILE_NAME}\n\n{existing}"
    );
    write_private(&path, &body)
}

/// A stable, ssh-safe `Host` alias for a profile.
fn unique_alias(profile: &Profile, used: &mut HashSet<String>) -> String {
    // Prefer the alias this connection already answers to, so importing a host
    // from the user's config and then editing it does not rename it.
    let preferred = profile
        .config_alias
        .clone()
        .unwrap_or_else(|| profile.name.clone());

    let mut base: String = preferred
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();
    base = base.trim_matches('-').to_string();
    if base.is_empty() {
        base = format!(
            "ez-{}",
            &profile.id.replace('-', "")[..8.min(profile.id.len())]
        );
    }

    let mut alias = base.clone();
    let mut n = 2;
    while !used.insert(alias.to_ascii_lowercase()) {
        alias = format!("{base}-{n}");
        n += 1;
    }
    alias
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, host: &str) -> Profile {
        Profile {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            host: host.into(),
            port: 22,
            username: "david".into(),
            auth: AuthMethod::Key,
            key_path: Some("/home/david/.ssh/id_ed25519".into()),
            tunnels: Vec::new(),
            last_connected: None,
            color: None,
            key_installed: false,
            from_config: false,
            config_alias: None,
            customized: true,
        }
    }

    fn tunnel(local: u16, remote: u16) -> Tunnel {
        Tunnel {
            id: uuid::Uuid::new_v4().to_string(),
            name: "cells".into(),
            local_port: local,
            remote_host: "localhost".into(),
            remote_port: remote,
            auto_start: true,
            scheme: "https".into(),
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("easyssh-ez-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_saved_connection_comes_back_whole() {
        let dir = tmpdir("roundtrip");
        let mut p = profile("cells models serv", "35.188.133.141");
        p.port = 2222;
        p.key_installed = true;
        p.last_connected = Some(42);
        p.tunnels.push(tunnel(4000, 4000));

        save(&dir, std::slice::from_ref(&p)).unwrap();
        let back = load(&dir);

        assert_eq!(back.len(), 1);
        let got = &back[0];
        assert_eq!(got.id, p.id);
        assert_eq!(got.name, "cells models serv");
        assert_eq!(got.host, "35.188.133.141");
        assert_eq!(got.port, 2222);
        assert_eq!(got.username, "david");
        assert_eq!(got.key_path, p.key_path);
        assert!(got.key_installed);
        assert_eq!(got.last_connected, Some(42));
        // The tunnel keeps the parts a LocalForward line cannot carry.
        assert_eq!(got.tunnels.len(), 1);
        assert_eq!(got.tunnels[0].id, p.tunnels[0].id);
        assert_eq!(got.tunnels[0].scheme, "https");
        assert!(got.tunnels[0].auto_start);
    }

    #[test]
    fn the_managed_file_is_real_ssh_config() {
        let dir = tmpdir("syntax");
        let mut p = profile("serv", "10.0.0.4");
        p.tunnels.push(tunnel(4000, 4000));
        save(&dir, &[p]).unwrap();

        let text = fs::read_to_string(path_for(&dir)).unwrap();
        assert!(text.contains("Host serv\n"), "{text}");
        assert!(text.contains("    HostName 10.0.0.4\n"), "{text}");
        assert!(text.contains("    User david\n"), "{text}");
        assert!(
            !text.contains("Port 22"),
            "the default port is noise: {text}"
        );
        assert!(
            text.contains("    LocalForward 127.0.0.1:4000 localhost:4000\n"),
            "{text}"
        );
    }

    #[test]
    fn the_users_config_gains_one_include_and_keeps_its_content() {
        let dir = tmpdir("include");
        fs::write(dir.join("config"), "Host mine\n    HostName example.com\n").unwrap();

        save(&dir, &[profile("a", "1.1.1.1")]).unwrap();
        save(&dir, &[profile("a", "1.1.1.1"), profile("b", "2.2.2.2")]).unwrap();

        let text = fs::read_to_string(dir.join("config")).unwrap();
        assert_eq!(
            text.matches("Include ez_config").count(),
            1,
            "the include must not accumulate: {text}"
        );
        assert!(
            text.contains("Host mine"),
            "the user's own hosts survive: {text}"
        );
        // And it comes before any Host block, or it would apply to that host only.
        assert!(text.find("Include").unwrap() < text.find("Host mine").unwrap());
    }

    #[test]
    fn two_connections_with_the_same_name_get_distinct_aliases() {
        let dir = tmpdir("aliases");
        save(
            &dir,
            &[profile("serv", "1.1.1.1"), profile("serv", "2.2.2.2")],
        )
        .unwrap();

        let text = fs::read_to_string(path_for(&dir)).unwrap();
        assert!(text.contains("Host serv\n"), "{text}");
        assert!(text.contains("Host serv-2\n"), "{text}");
        assert_eq!(load(&dir).len(), 2);
    }

    #[test]
    fn a_forward_added_by_hand_shows_up_as_a_tunnel() {
        let dir = tmpdir("handedit");
        save(&dir, &[profile("serv", "1.1.1.1")]).unwrap();

        let text = fs::read_to_string(path_for(&dir)).unwrap();
        fs::write(
            path_for(&dir),
            format!("{text}    LocalForward 9000 127.0.0.1:9000\n"),
        )
        .unwrap();

        let back = load(&dir);
        assert_eq!(back[0].tunnels.len(), 1);
        assert_eq!(back[0].tunnels[0].local_port, 9000);
        assert_eq!(back[0].tunnels[0].remote_host, "127.0.0.1");
    }

    #[test]
    fn our_own_hosts_do_not_come_back_as_config_hosts() {
        let dir = tmpdir("noecho");
        fs::write(dir.join("config"), "Host mine\n    HostName example.com\n").unwrap();
        save(&dir, &[profile("serv", "1.1.1.1")]).unwrap();

        // The config now includes ez_config, so a parser that followed it would
        // list `serv` a second time as a host merely defined in the config.
        let hosts = crate::sshconfig::parse_config(&dir.join("config")).unwrap();
        let aliases: Vec<&str> = hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(
            aliases,
            ["mine"],
            "easySSH's own hosts must not be re-listed"
        );
    }

    #[test]
    fn config_derived_entries_are_not_written() {
        let dir = tmpdir("derived");
        let mut derived = profile("from-config", "3.3.3.3");
        derived.from_config = true;
        save(&dir, &[profile("owned", "1.1.1.1"), derived]).unwrap();

        let text = fs::read_to_string(path_for(&dir)).unwrap();
        assert!(text.contains("Host owned"));
        assert!(!text.contains("from-config"), "{text}");
    }
}
