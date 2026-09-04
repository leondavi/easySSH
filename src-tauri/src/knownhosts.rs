//! Reading and editing the `known_hosts` file for the selected `.ssh` location.
//!
//! The common reason to come here is a host whose key has changed: easySSH
//! refuses that connection, and the fix is to delete the stale entry after you
//! have satisfied yourself the change was legitimate.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use ssh_key::PublicKey;

use crate::model::{KnownHost, KnownHostRef, Profile};

pub fn path_for(dir: &Path) -> PathBuf {
    dir.join("known_hosts")
}

/// Every entry in the file, in file order.
///
/// Lines we cannot parse are still returned, marked `parsed: false`, so the
/// list always accounts for the whole file — an entry the UI silently dropped
/// would be one the user cannot remove.
pub fn list(dir: &Path, profiles: &[Profile]) -> Result<Vec<KnownHost>> {
    let path = path_for(dir);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;

    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        out.push(parse_line(line, trimmed, profiles));
    }
    Ok(out)
}

fn parse_line(line: usize, raw: &str, profiles: &[Profile]) -> KnownHost {
    let unparsed = |fingerprint: String| KnownHost {
        line,
        hosts: Vec::new(),
        hashed: false,
        marker: None,
        algorithm: String::new(),
        fingerprint,
        comment: String::new(),
        used_by: Vec::new(),
        parsed: false,
    };

    let mut tokens = raw.split_whitespace().peekable();

    // An optional @cert-authority or @revoked marker comes first.
    let mut marker = None;
    if let Some(first) = tokens.peek() {
        if let Some(name) = first.strip_prefix('@') {
            marker = Some(name.to_string());
            tokens.next();
        }
    }

    let Some(host_field) = tokens.next() else {
        return unparsed(String::new());
    };
    let Some(algorithm) = tokens.next() else {
        return unparsed(String::new());
    };
    let Some(body) = tokens.next() else {
        return unparsed(String::new());
    };
    let comment = tokens.collect::<Vec<_>>().join(" ");

    // `|1|salt|hash` entries are HashKnownHosts output: the name is one-way
    // hashed, so it can be removed but never displayed.
    let hashed = host_field.starts_with("|1|");
    let hosts: Vec<String> = if hashed {
        Vec::new()
    } else {
        host_field.split(',').map(pretty_host).collect()
    };

    let fingerprint = PublicKey::from_openssh(&format!("{algorithm} {body}"))
        .map(|k| k.fingerprint(Default::default()).to_string())
        .unwrap_or_default();

    // Point out which saved connections rely on this entry.
    let used_by = profiles
        .iter()
        .filter(|p| hosts.iter().any(|h| matches_profile(h, p)))
        .map(|p| p.name.clone())
        .collect();

    KnownHost {
        line,
        hosts,
        hashed,
        marker,
        algorithm: algorithm.to_string(),
        fingerprint,
        comment,
        used_by,
        parsed: true,
    }
}

/// `[example.com]:2222` is how a non-default port is recorded; show it as
/// `example.com:2222`.
fn pretty_host(entry: &str) -> String {
    match entry
        .strip_prefix('[')
        .and_then(|rest| rest.split_once("]:"))
    {
        Some((host, port)) => format!("{host}:{port}"),
        None => entry.to_string(),
    }
}

fn matches_profile(entry: &str, profile: &Profile) -> bool {
    let (host, port) = match entry.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h, port),
            Err(_) => (entry, 22),
        },
        None => (entry, 22),
    };
    port == profile.port && host.eq_ignore_ascii_case(&profile.host)
}

/// Remove the given entries and return how many lines were deleted.
///
/// Each reference carries the fingerprint the UI displayed. If the file has
/// changed since it was listed, the fingerprints will not line up and we
/// refuse the whole operation rather than delete something the user never saw.
pub fn remove(dir: &Path, refs: &[KnownHostRef]) -> Result<usize> {
    if refs.is_empty() {
        return Ok(0);
    }
    let path = path_for(dir);
    if !path.is_file() {
        return Err(anyhow!("{} does not exist", path.display()));
    }

    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let lines: Vec<&str> = text.lines().collect();

    let mut targets = std::collections::HashSet::new();
    for r in refs {
        let Some(raw) = lines.get(r.line.wrapping_sub(1)) else {
            return Err(anyhow!(
                "{} has changed since the list was loaded — reopen it and try again",
                path.display()
            ));
        };
        // An empty expected fingerprint means the line never parsed; match on
        // the line's own content instead so those can still be removed.
        let current = parse_line(r.line, raw.trim(), &[]);
        if current.fingerprint != r.fingerprint {
            return Err(anyhow!(
                "{} has changed since the list was loaded — reopen it and try again",
                path.display()
            ));
        }
        targets.insert(r.line);
    }

    // Keep a copy of what we are about to modify. Losing a known_hosts file to
    // a mistake here should be recoverable.
    let backup = path.with_extension("easyssh-backup");
    fs::write(&backup, &text).with_context(|| format!("writing {}", backup.display()))?;

    let kept: Vec<&str> = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| !targets.contains(&(i + 1)))
        .map(|(_, l)| *l)
        .collect();

    let mut body = kept.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }

    // Write-then-rename so an interrupted write cannot truncate the file.
    let tmp = path.with_extension("easyssh-tmp");
    fs::write(&tmp, &body).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }

    Ok(targets.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEX";

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("easyssh-kh-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(dir: &Path, body: &str) {
        fs::write(path_for(dir), body).unwrap();
    }

    #[test]
    fn a_missing_file_is_an_empty_list_not_an_error() {
        let dir = tmpdir("missing");
        assert!(list(&dir, &[]).unwrap().is_empty());
    }

    #[test]
    fn parses_hosts_ports_markers_and_hashed_entries() {
        let dir = tmpdir("parse");
        write(
            &dir,
            &format!(
                "# a comment\n\
             example.com {ED} me@laptop\n\
             [other.example]:2222 {ED}\n\
             @revoked bad.example {ED}\n\
             |1|abcdef=|ghijkl= {ED}\n"
            ),
        );
        let entries = list(&dir, &[]).unwrap();
        assert_eq!(entries.len(), 4);

        // Comments and blank lines are skipped, so line numbers must come from
        // the file, not from the position in this list.
        assert_eq!(entries[0].line, 2);
        assert_eq!(entries[0].hosts, vec!["example.com"]);
        assert_eq!(entries[0].comment, "me@laptop");

        // `[host]:port` is shown in the readable form.
        assert_eq!(entries[1].hosts, vec!["other.example:2222"]);

        assert_eq!(entries[2].marker.as_deref(), Some("revoked"));
        assert_eq!(entries[2].hosts, vec!["bad.example"]);

        assert!(entries[3].hashed);
        assert!(entries[3].hosts.is_empty());
    }

    #[test]
    fn removes_only_the_requested_lines_and_keeps_a_backup() {
        let dir = tmpdir("remove");
        write(
            &dir,
            &format!("a.example {ED}\nb.example {ED}\nc.example {ED}\n"),
        );

        let entries = list(&dir, &[]).unwrap();
        let target = entries.iter().find(|e| e.hosts == ["b.example"]).unwrap();
        let refs = vec![KnownHostRef {
            line: target.line,
            fingerprint: target.fingerprint.clone(),
        }];

        assert_eq!(remove(&dir, &refs).unwrap(), 1);

        let left = list(&dir, &[]).unwrap();
        let hosts: Vec<&str> = left.iter().map(|e| e.hosts[0].as_str()).collect();
        assert_eq!(hosts, vec!["a.example", "c.example"]);

        // The original is recoverable.
        let backup = fs::read_to_string(path_for(&dir).with_extension("easyssh-backup")).unwrap();
        assert!(backup.contains("b.example"));
    }

    #[test]
    fn refuses_to_delete_when_the_file_moved_underneath() {
        let dir = tmpdir("stale");
        write(&dir, &format!("a.example {ED}\nb.example {ED}\n"));
        let entries = list(&dir, &[]).unwrap();
        let target = entries[1].clone();

        // Someone edits the file behind our back: line 2 is now a different host.
        write(&dir, &format!("a.example {ED}\n"));

        let refs = vec![KnownHostRef {
            line: target.line,
            fingerprint: target.fingerprint,
        }];
        assert!(remove(&dir, &refs).is_err());

        // Nothing was touched.
        assert_eq!(list(&dir, &[]).unwrap().len(), 1);
    }

    #[test]
    fn removing_the_last_entry_leaves_an_empty_file() {
        let dir = tmpdir("last");
        write(&dir, &format!("only.example {ED}\n"));
        let entries = list(&dir, &[]).unwrap();
        let refs = vec![KnownHostRef {
            line: entries[0].line,
            fingerprint: entries[0].fingerprint.clone(),
        }];

        assert_eq!(remove(&dir, &refs).unwrap(), 1);
        assert_eq!(fs::read_to_string(path_for(&dir)).unwrap(), "");
        assert!(list(&dir, &[]).unwrap().is_empty());
    }
}
