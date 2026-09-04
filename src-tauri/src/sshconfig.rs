//! Finding `.ssh` directories on this machine and reading OpenSSH `config` files.
//!
//! The parser covers the subset of `ssh_config(5)` that maps onto an easySSH
//! profile — `Host`, `HostName`, `User`, `Port`, `IdentityFile` — and follows
//! `Include` directives. Directives it does not understand are skipped rather
//! than treated as errors, because a config full of `ProxyJump` and
//! `ControlMaster` lines should still yield its host list.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::model::{SshHostEntry, SshLocation};

/// Directive values collected for one `Host` block.
#[derive(Default, Clone)]
struct Block {
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    source: String,
}

impl Block {
    /// Fill anything unset from `other` — how OpenSSH applies `Host *` defaults.
    fn inherit(&mut self, other: &Block) {
        self.hostname
            .get_or_insert_with(|| other.hostname.clone().unwrap_or_default());
        if self.hostname.as_deref() == Some("") {
            self.hostname = None;
        }
        if self.user.is_none() {
            self.user = other.user.clone();
        }
        if self.port.is_none() {
            self.port = other.port;
        }
        if self.identity_file.is_none() {
            self.identity_file = other.identity_file.clone();
        }
    }
}

// ─────────────────────────────────────────────────────────── locations

/// Every plausible `.ssh` directory for this OS, most relevant first.
///
/// The first entry is the conventional per-user directory and is what easySSH
/// selects unless the user picks another.
pub fn discover_locations() -> Vec<SshLocation> {
    let mut candidates: Vec<(PathBuf, String, String)> = Vec::new();
    let mut push = |dir: PathBuf, label: &str, scope: &str| {
        candidates.push((dir, label.to_string(), scope.to_string()));
    };

    if let Some(home) = dirs::home_dir() {
        push(home.join(".ssh"), "Personal", "user");
    }

    #[cfg(target_os = "windows")]
    {
        // Windows has three common homes for SSH material, and which one is in
        // play depends on whether you use OpenSSH for Windows, Git Bash, or WSL.
        if let Ok(profile) = std::env::var("USERPROFILE") {
            push(PathBuf::from(&profile).join(".ssh"), "User profile", "user");
        }
        if let Ok(data) = std::env::var("ProgramData") {
            push(
                PathBuf::from(&data).join("ssh"),
                "System (OpenSSH)",
                "system",
            );
        }
        for git in [
            "C:\\Program Files\\Git\\etc\\ssh",
            "C:\\Program Files (x86)\\Git\\etc\\ssh",
        ] {
            push(PathBuf::from(git), "Git for Windows", "system");
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        push(PathBuf::from("/etc/ssh"), "System", "system");
    }

    // An explicit override always wins and is listed first.
    if let Ok(custom) = std::env::var("EASYSSH_SSH_DIR") {
        if !custom.is_empty() {
            candidates.insert(
                0,
                (
                    PathBuf::from(custom),
                    "Custom (EASYSSH_SSH_DIR)".into(),
                    "user".into(),
                ),
            );
        }
    }

    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (dir, label, scope) in candidates {
        let canonical = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        if !seen.insert(canonical) {
            continue; // e.g. HOME and USERPROFILE pointing at the same place
        }
        out.push(describe(&dir, &label, &scope, out.is_empty()));
    }
    out
}

/// Build the `SshLocation` for a directory, counting what is inside it.
pub fn describe(dir: &Path, label: &str, scope: &str, is_default: bool) -> SshLocation {
    let config_path = config_path_for(dir);
    let dir_exists = dir.is_dir();
    let config_exists = config_path.is_file();

    let key_count = if dir_exists {
        crate::keys::list_keys_in(dir).map(|k| k.len()).unwrap_or(0)
    } else {
        0
    };
    let host_count = if config_exists {
        parse_config(&config_path).map(|h| h.len()).unwrap_or(0)
    } else {
        0
    };

    let display = dir.display().to_string();
    let short = shorten(&display);

    SshLocation {
        id: display.clone(),
        label: format!("{label} ({short})"),
        dir: display,
        config_path: config_path.display().to_string(),
        dir_exists,
        config_exists,
        key_count,
        host_count,
        is_default,
        scope: scope.to_string(),
    }
}

/// System directories hold `ssh_config`; user directories hold `config`.
pub fn config_path_for(dir: &Path) -> PathBuf {
    let user = dir.join("config");
    if user.is_file() {
        return user;
    }
    let system = dir.join("ssh_config");
    if system.is_file() {
        return system;
    }
    user
}

/// Replace the home prefix with `~` so labels stay readable.
fn shorten(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        let home = home.display().to_string();
        if let Some(rest) = path.strip_prefix(&home) {
            return format!("~{rest}");
        }
    }
    path.to_string()
}

/// Look up one location by its directory, for when the user has pinned a choice.
pub fn location_for_dir(dir: &Path) -> SshLocation {
    let known = discover_locations();
    if let Some(found) = known.iter().find(|l| Path::new(&l.dir) == dir) {
        return found.clone();
    }
    describe(dir, "Custom", "user", false)
}

// ─────────────────────────────────────────────────────────── parsing

/// Parse a config file into host entries, following `Include` directives.
pub fn parse_config(path: &Path) -> Result<Vec<SshHostEntry>> {
    let mut blocks: Vec<(Vec<String>, Block)> = Vec::new();
    let mut visited = Vec::new();
    collect(path, &mut blocks, &mut visited, 0);

    // `Host *` supplies defaults for everything else.
    let defaults = blocks
        .iter()
        .find(|(patterns, _)| patterns.iter().any(|p| p == "*"))
        .map(|(_, b)| b.clone())
        .unwrap_or_default();

    let mut out: Vec<SshHostEntry> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (patterns, block) in &blocks {
        for pattern in patterns {
            // Patterns and negations are matching rules, not hosts you can dial.
            if pattern.contains('*') || pattern.contains('?') || pattern.starts_with('!') {
                continue;
            }
            if !seen.insert(pattern.clone()) {
                continue; // first block wins, as OpenSSH does
            }

            let mut resolved = block.clone();
            resolved.inherit(&defaults);

            out.push(SshHostEntry {
                alias: pattern.clone(),
                // With no explicit HostName, `ssh myalias` connects to "myalias".
                hostname: resolved.hostname.clone().unwrap_or_else(|| pattern.clone()),
                user: resolved.user.clone(),
                port: resolved.port.unwrap_or(22),
                identity_file: resolved.identity_file.clone().map(|p| expand(&p)),
                source: block.source.clone(),
                already_imported: false,
                auto_auth: false,
                auth_note: String::new(),
            });
        }
    }

    Ok(out)
}

/// Read one file into `blocks`, recursing through `Include`.
fn collect(
    path: &Path,
    blocks: &mut Vec<(Vec<String>, Block)>,
    visited: &mut Vec<PathBuf>,
    depth: usize,
) {
    // OpenSSH caps Include nesting; so do we, and a cycle would otherwise hang.
    if depth > 8 {
        return;
    }
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if visited.contains(&canonical) {
        return;
    }
    visited.push(canonical);

    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let source = path.display().to_string();
    let mut current: Option<(Vec<String>, Block)> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((keyword, value)) = split_directive(line) else {
            continue;
        };
        let key = keyword.to_ascii_lowercase();

        match key.as_str() {
            "host" => {
                if let Some(block) = current.take() {
                    blocks.push(block);
                }
                let patterns: Vec<String> =
                    value.split_whitespace().map(|s| s.to_string()).collect();
                current = Some((
                    patterns,
                    Block {
                        source: source.clone(),
                        ..Default::default()
                    },
                ));
            }
            // A `Match` block's conditions are evaluated at connect time; we cannot
            // resolve them here, so we simply stop attributing lines to a Host.
            "match" => {
                if let Some(block) = current.take() {
                    blocks.push(block);
                }
            }
            "include" => {
                for pattern in value.split_whitespace() {
                    for included in resolve_include(pattern, path) {
                        collect(&included, blocks, visited, depth + 1);
                    }
                }
            }
            _ => {
                let Some((_, block)) = current.as_mut() else {
                    continue; // a directive before any Host is a global default we ignore
                };
                match key.as_str() {
                    "hostname" => block.hostname = Some(value.to_string()),
                    "user" => block.user = Some(value.to_string()),
                    "port" => block.port = value.parse().ok(),
                    // Only the first IdentityFile is offered in the UI; ssh would try all.
                    "identityfile" if block.identity_file.is_none() => {
                        block.identity_file = Some(unquote(value));
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some(block) = current.take() {
        blocks.push(block);
    }
}

/// `Key value`, `Key = value` and `Key=value` are all legal.
fn split_directive(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    let end = bytes
        .iter()
        .position(|c| c.is_ascii_whitespace() || *c == b'=')?;
    let keyword = &line[..end];
    let rest = line[end..].trim_start_matches([' ', '\t', '=']).trim();
    if keyword.is_empty() || rest.is_empty() {
        return None;
    }
    Some((keyword, rest))
}

fn unquote(s: &str) -> String {
    s.trim_matches('"').to_string()
}

/// Expand `~` and, on Windows, `%USERPROFILE%`-style paths.
fn expand(path: &str) -> String {
    let path = unquote(path);
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).display().to_string();
        }
    }
    path
}

/// Resolve an `Include` pattern, which may be relative to the config's directory
/// and may end in a `*` glob.
fn resolve_include(pattern: &str, from: &Path) -> Vec<PathBuf> {
    let expanded = expand(pattern);
    let candidate = Path::new(&expanded);

    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        from.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    };

    let name = absolute
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if !name.contains('*') && !name.contains('?') {
        return if absolute.is_file() {
            vec![absolute]
        } else {
            Vec::new()
        };
    }

    // Shallow glob on the last path segment — the only form seen in practice.
    let dir = absolute.parent().unwrap_or_else(|| Path::new("."));
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            p.file_name()
                .map(|n| glob_match(&name, &n.to_string_lossy()))
                .unwrap_or(false)
        })
        .collect();
    out.sort();
    out
}

/// `*` and `?` matching, which is all ssh config globs use.
fn glob_match(pattern: &str, text: &str) -> bool {
    fn go(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => go(&p[1..], t) || (!t.is_empty() && go(p, &t[1..])),
            Some('?') => !t.is_empty() && go(&p[1..], &t[1..]),
            Some(c) => t.first() == Some(c) && go(&p[1..], &t[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    go(&p, &t)
}

/// Host entries for a location, marking the ones easySSH already knows about.
pub fn hosts_for(dir: &Path, existing: &[crate::model::Profile]) -> Result<Vec<SshHostEntry>> {
    let path = config_path_for(dir);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let mut hosts = parse_config(&path)?;

    let known: HashMap<(String, u16), ()> = existing
        .iter()
        .map(|p| ((p.host.to_ascii_lowercase(), p.port), ()))
        .collect();

    for h in &mut hosts {
        h.already_imported = known.contains_key(&(h.hostname.to_ascii_lowercase(), h.port));
        let (auto, note) = auth_status(h, dir);
        h.auto_auth = auto;
        h.auth_note = note;
    }
    Ok(hosts)
}

// ─────────────────────────────────────── auth status and writing back

/// Key names OpenSSH tries by default when a Host block names no IdentityFile.
const DEFAULT_IDENTITIES: &[&str] = &[
    "id_ed25519",
    "id_ecdsa",
    "id_rsa",
    crate::keys::DEFAULT_KEY_NAME,
];

/// Decide whether a config host would log in without a password prompt.
///
/// This is a best-effort read of the local side only — we cannot know what is
/// in the server's `authorized_keys` without connecting — so the note says
/// which key ssh would offer rather than promising it will be accepted.
fn auth_status(entry: &SshHostEntry, dir: &Path) -> (bool, String) {
    if let Some(identity) = &entry.identity_file {
        let path = Path::new(identity);
        return if path.is_file() {
            (true, format!("IdentityFile {}", file_label(path)))
        } else {
            (
                false,
                format!("IdentityFile {} is missing", file_label(path)),
            )
        };
    }

    for name in DEFAULT_IDENTITIES {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return (true, format!("default key {name}"));
        }
    }
    (false, "no key configured — password login".to_string())
}

fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

/// Does this config already have a `Host` block with this alias?
pub fn has_host(dir: &Path, alias: &str) -> bool {
    let path = config_path_for(dir);
    parse_config(&path)
        .map(|hosts| hosts.iter().any(|h| h.alias.eq_ignore_ascii_case(alias)))
        .unwrap_or(false)
}

/// Append a `Host` block for a profile so plain `ssh <alias>` works from any
/// terminal from now on. Returns the block that was written.
///
/// Refuses rather than edits when the alias is already present: rewriting a
/// user's existing block is not something to do behind their back.
pub fn append_host(
    dir: &Path,
    alias: &str,
    profile: &crate::model::Profile,
    include_tunnels: bool,
) -> Result<String> {
    let alias = alias.trim();
    if alias.is_empty() {
        return Err(anyhow::anyhow!("the ssh alias cannot be empty"));
    }
    if alias.split_whitespace().count() != 1 {
        return Err(anyhow::anyhow!("the ssh alias cannot contain spaces"));
    }
    if has_host(dir, alias) {
        return Err(anyhow::anyhow!(
            "'{alias}' is already in {}. Pick another alias, or edit that block by hand.",
            config_path_for(dir).display()
        ));
    }

    let mut block = String::new();
    block.push_str(&format!("\n# Added by easySSH\nHost {alias}\n"));
    block.push_str(&format!("    HostName {}\n", profile.host));
    block.push_str(&format!("    User {}\n", profile.username));
    if profile.port != 22 {
        block.push_str(&format!("    Port {}\n", profile.port));
    }
    if profile.auth == crate::model::AuthMethod::Key {
        if let Some(key) = &profile.key_path {
            block.push_str(&format!("    IdentityFile {key}\n"));
            // Without this ssh offers every agent key first and may hit MaxAuthTries.
            block.push_str("    IdentitiesOnly yes\n");
        }
    }
    if include_tunnels {
        for t in &profile.tunnels {
            block.push_str(&format!(
                "    LocalForward 127.0.0.1:{} {}:{}\n",
                t.local_port, t.remote_host, t.remote_port
            ));
        }
    }

    crate::keys::ensure_dir(dir)?;
    let path = config_path_for(dir);

    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(block.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }

    Ok(block.trim_start_matches('\n').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("easyssh-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn parses_hosts_and_applies_wildcard_defaults() {
        let dir = tmpdir("basic");
        let cfg = write(
            &dir,
            "config",
            "\
Host *
    User fallback
    Port 2200

Host web
    HostName 10.0.0.5
    User deploy

Host bare

Host db
    Hostname=db.internal
    Port 5432
    IdentityFile ~/.ssh/id_db
",
        );
        let hosts = parse_config(&cfg).unwrap();
        let get = |a: &str| hosts.iter().find(|h| h.alias == a).unwrap().clone();

        // Explicit values win; unset ones fall back to `Host *`.
        let web = get("web");
        assert_eq!(web.hostname, "10.0.0.5");
        assert_eq!(web.user.as_deref(), Some("deploy"));
        assert_eq!(web.port, 2200);

        // No HostName: the alias itself is the host.
        assert_eq!(get("bare").hostname, "bare");
        assert_eq!(get("bare").user.as_deref(), Some("fallback"));

        // `Key=value` form, and ~ expansion on IdentityFile.
        let db = get("db");
        assert_eq!(db.hostname, "db.internal");
        assert_eq!(db.port, 5432);
        assert!(db.identity_file.unwrap().ends_with("id_db"));

        // The wildcard pattern is not itself a connectable host.
        assert!(!hosts.iter().any(|h| h.alias == "*"));
    }

    #[test]
    fn follows_include_globs_without_looping() {
        let dir = tmpdir("include");
        fs::create_dir_all(dir.join("conf.d")).unwrap();
        write(
            &dir,
            "config",
            "Include conf.d/*.conf\nInclude config\n\nHost main\n  HostName main.example\n",
        );
        write(
            &dir.join("conf.d"),
            "a.conf",
            "Host alpha\n  HostName alpha.example\n",
        );
        write(
            &dir.join("conf.d"),
            "b.conf",
            "Host beta\n  HostName beta.example\n",
        );
        write(
            &dir.join("conf.d"),
            "skip.txt",
            "Host ignored\n  HostName no.example\n",
        );

        let hosts = parse_config(&dir.join("config")).unwrap();
        let aliases: Vec<_> = hosts.iter().map(|h| h.alias.as_str()).collect();

        assert!(aliases.contains(&"alpha"));
        assert!(aliases.contains(&"beta"));
        assert!(aliases.contains(&"main"));
        // Only *.conf matched the glob.
        assert!(!aliases.contains(&"ignored"));
    }

    #[test]
    fn match_block_does_not_leak_into_the_previous_host() {
        let dir = tmpdir("match");
        let cfg = write(
            &dir,
            "config",
            "\
Host web
    HostName web.example
Match host nothing
    User sneaky
",
        );
        let hosts = parse_config(&cfg).unwrap();
        let web = hosts.iter().find(|h| h.alias == "web").unwrap();
        assert_eq!(web.user, None);
    }

    #[test]
    fn glob_matches_stars_and_question_marks() {
        assert!(glob_match("*.conf", "a.conf"));
        assert!(!glob_match("*.conf", "a.txt"));
        assert!(glob_match("id_?", "id_a"));
        assert!(!glob_match("id_?", "id_ab"));
        assert!(glob_match("*", "anything"));
    }
}
