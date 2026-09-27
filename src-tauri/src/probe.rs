//! Background health checks, so the sidebar can say which servers are up and
//! which will let you in without a password.
//!
//! Two separate questions are answered, on different schedules:
//!
//! * **Reachable** — can we open a TCP connection to the SSH port? Cheap, so it
//!   runs often. A TCP connect is used rather than ICMP: it needs no elevated
//!   privileges, works the same on macOS and Windows, and tests the port that
//!   actually matters instead of merely whether the host answers pings.
//! * **Key login** — does the configured private key actually get us in? That
//!   costs a full SSH handshake, so it runs rarely and only when there is no
//!   live session to piggyback on.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::keys;
use crate::model::Profile;
use crate::ssh::{self, HostKeyPolicy};

/// Long enough to cross a slow link, short enough that a dead host does not
/// hold up the rest of the sweep.
const TCP_TIMEOUT: Duration = Duration::from_secs(4);

/// Can we open a TCP connection to the host's SSH port?
pub async fn reachable(host: &str, port: u16) -> bool {
    let addr = format!("{host}:{port}");
    matches!(
        tokio::time::timeout(TCP_TIMEOUT, tokio::net::TcpStream::connect(&addr)).await,
        Ok(Ok(_))
    )
}

/// The outcome of asking whether a key gets us in.
pub enum KeyAuth {
    /// This key authenticated. Passwordless login works.
    Works(PathBuf),
    /// We got far enough to be told no. Carries a reason for the tooltip.
    Refused(String),
    /// We could not find out — host down, no usable key, host not yet known.
    /// Distinct from `Refused` so the UI can show "unknown" rather than
    /// claiming passwordless login is broken.
    Unknown(String),
}

/// The keys worth offering to a host, best first: the one the connection is
/// set to use, then the other keys in the `.ssh` directory in focus.
///
/// Keys that need a passphrase are left out — they cannot be tried without
/// asking — and so are duplicates of the connection's own key.
pub fn candidates(profile: &Profile, ssh_dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let same = |a: &Path, b: &Path| match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    };

    if let Some(own) = profile.key_path.as_deref().map(PathBuf::from) {
        if own.is_file() {
            out.push(own);
        }
    }
    for key in keys::list_keys_in(ssh_dir).unwrap_or_default() {
        let path = PathBuf::from(&key.path);
        if !key.encrypted && !out.iter().any(|p| same(p, &path)) {
            out.push(path);
        }
    }
    out.truncate(ssh::MAX_KEYS_OFFERED);
    out
}

/// Does any key on this machine already log in to this host?
///
/// Used both to confirm that a connection's own key still works and to notice
/// that one set to use a password does not need it — a server set up by hand,
/// by another tool, or by an earlier easySSH, already trusts a key here.
pub async fn key_auth(
    profile: &Profile,
    ssh_dir: &Path,
    known_hosts: &Path,
    policy: HostKeyPolicy,
) -> KeyAuth {
    let candidates = candidates(profile, ssh_dir);
    if candidates.is_empty() {
        return match profile.key_path.as_deref() {
            Some(k) if !Path::new(k).is_file() => KeyAuth::Refused(format!("{k} is missing")),
            _ => {
                KeyAuth::Unknown("no key on this machine can be tried without a passphrase".into())
            }
        };
    }

    match ssh::find_working_key(
        &profile.host,
        profile.port,
        &profile.username,
        &candidates,
        known_hosts,
        policy,
    )
    .await
    {
        Ok(Some((path, session))) => {
            ssh::disconnect(&session.handle).await;
            KeyAuth::Works(path)
        }
        Ok(None) => KeyAuth::Refused(if candidates.len() == 1 {
            "the server did not accept the key".into()
        } else {
            format!(
                "the server accepted none of {} keys on this machine",
                candidates.len()
            )
        }),
        Err(e) => {
            let msg = format!("{e:#}");
            // An unreachable host says nothing about whether a key would work.
            if msg.contains("timed out") || msg.contains("could not reach") {
                KeyAuth::Unknown("the host was not reachable".into())
            } else if msg.contains("Not allowed by") || msg.contains("host key") {
                KeyAuth::Unknown("this host is not in known_hosts yet".into())
            } else {
                KeyAuth::Refused(msg)
            }
        }
    }
}

/// How long to wait before re-testing key login after a given number of
/// consecutive failures.
///
/// Backing off matters here: a key that is genuinely rejected would otherwise
/// produce a failed authentication every five minutes forever, which is exactly
/// the pattern fail2ban and friends are built to ban.
pub fn backoff(consecutive_failures: u32) -> Duration {
    match consecutive_failures {
        0 => Duration::from_secs(5 * 60),
        1 => Duration::from_secs(10 * 60),
        2 => Duration::from_secs(20 * 60),
        _ => Duration::from_secs(60 * 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AuthMethod;
    use crate::testserver as harness;

    /// A fresh `.ssh` directory holding one unencrypted key per name.
    fn keys_dir(tag: &str, names: &[&str]) -> (PathBuf, Vec<String>) {
        let dir =
            std::env::temp_dir().join(format!("easyssh-discover-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = names
            .iter()
            .map(|n| {
                crate::keys::generate(&dir, n, "ed25519", "test", None)
                    .unwrap()
                    .path
            })
            .collect();
        (dir, paths)
    }

    fn profile(port: u16, auth: AuthMethod, key_path: Option<String>) -> Profile {
        Profile {
            id: "p".into(),
            name: "Box".into(),
            host: "127.0.0.1".into(),
            port,
            username: "someone".into(),
            auth,
            key_path,
            tunnels: Vec::new(),
            last_connected: None,
            color: None,
            key_installed: false,
            from_config: false,
            config_alias: None,
            customized: true,
        }
    }

    /// The headline case: a connection set to use a password, on a server that
    /// already trusts a key sitting in `~/.ssh`. That key is found, and every
    /// candidate is offered over a single connection, as `ssh` itself does.
    #[tokio::test]
    async fn finds_a_key_the_server_already_trusts_for_a_password_connection() {
        let (dir, paths) = keys_dir("found", &["alpha", "bravo", "charlie"]);
        let trusted = crate::keys::public_key_for(Path::new(&paths[2])).unwrap();
        let server = harness::start_trusting(trusted).await;
        let kh = harness::known_hosts("discover-found");

        let outcome = key_auth(
            &profile(server.port, AuthMethod::Password, None),
            &dir,
            &kh,
            HostKeyPolicy::LearnUnknown,
        )
        .await;

        match outcome {
            KeyAuth::Works(path) => assert_eq!(path, PathBuf::from(&paths[2])),
            KeyAuth::Refused(w) | KeyAuth::Unknown(w) => panic!("no key found: {w}"),
        }
        assert_eq!(
            server
                .connections
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "each key was tried on its own connection"
        );
    }

    #[tokio::test]
    async fn a_server_that_trusts_none_of_the_keys_is_a_refusal() {
        let (dir, _) = keys_dir("none", &["alpha", "bravo"]);
        let (_, other) = keys_dir("none-other", &["stranger"]);
        let server =
            harness::start_trusting(crate::keys::public_key_for(Path::new(&other[0])).unwrap())
                .await;
        let kh = harness::known_hosts("discover-none");

        let outcome = key_auth(
            &profile(server.port, AuthMethod::Password, None),
            &dir,
            &kh,
            HostKeyPolicy::LearnUnknown,
        )
        .await;
        assert!(
            matches!(outcome, KeyAuth::Refused(_)),
            "should be a refusal"
        );
    }

    /// The key the connection is set to use goes first, even from outside the
    /// `.ssh` directory, and is not offered twice.
    #[test]
    fn the_connections_own_key_is_offered_first_and_once() {
        let (dir, paths) = keys_dir("order", &["alpha", "bravo"]);
        let own = paths[1].clone();
        let got = candidates(&profile(22, AuthMethod::Key, Some(own.clone())), &dir);
        assert_eq!(got[0], PathBuf::from(&own));
        assert_eq!(got.len(), 2, "the own key was listed twice: {got:?}");
    }

    /// A passphrase cannot be typed by a background check, so such a key is
    /// never offered — and the cap keeps a full `.ssh` under `MaxAuthTries`.
    #[test]
    fn passphrase_keys_are_skipped_and_the_list_is_capped() {
        let (dir, _) = keys_dir("cap", &["k1", "k2", "k3", "k4", "k5", "k6", "k7"]);
        crate::keys::generate(&dir, "locked", "ed25519", "test", Some("secret")).unwrap();
        let got = candidates(&profile(22, AuthMethod::Password, None), &dir);
        assert_eq!(got.len(), ssh::MAX_KEYS_OFFERED);
        assert!(
            !got.iter().any(|p| p.ends_with("locked")),
            "a passphrase key was offered"
        );
    }

    #[tokio::test]
    async fn a_closed_port_is_not_reachable() {
        // Bind and drop, so the port is almost certainly free and refusing.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        assert!(!reachable("127.0.0.1", port).await);
    }

    #[tokio::test]
    async fn a_listening_port_is_reachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        assert!(reachable("127.0.0.1", port).await);
    }

    #[tokio::test]
    async fn an_unresolvable_host_is_not_reachable() {
        assert!(!reachable("no-such-host.easyssh.invalid", 22).await);
    }

    #[test]
    fn backoff_grows_with_consecutive_failures() {
        assert!(backoff(1) > backoff(0));
        assert!(backoff(2) > backoff(1));
        // And is capped, so it never stops checking altogether.
        assert_eq!(backoff(9), backoff(3));
    }
}
