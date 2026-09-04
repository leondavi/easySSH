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

use std::path::Path;
use std::time::Duration;

use crate::model::{AuthMethod, Profile};
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
    /// The key authenticated. Passwordless login works.
    Works,
    /// We got far enough to be told no. Carries a reason for the tooltip.
    Refused(String),
    /// We could not find out — host down, key missing, host not yet known.
    /// Distinct from `Refused` so the UI can show "unknown" rather than
    /// claiming passwordless login is broken.
    Unknown(String),
}

/// Try a key login and hang up immediately.
///
/// Uses `RequireKnown`, so a host easySSH has never seen is reported as unknown
/// rather than being silently pinned behind the user's back.
pub async fn key_auth(profile: &Profile, known_hosts: &Path) -> KeyAuth {
    if profile.auth != AuthMethod::Key {
        return KeyAuth::Unknown("this connection uses a password".into());
    }
    let Some(key_path) = profile.key_path.as_deref() else {
        return KeyAuth::Unknown("no key is selected".into());
    };
    if !Path::new(key_path).is_file() {
        return KeyAuth::Refused(format!("{key_path} is missing"));
    }

    match ssh::connect_key(
        &profile.host,
        profile.port,
        &profile.username,
        Path::new(key_path),
        None,
        known_hosts,
        HostKeyPolicy::RequireKnown,
    )
    .await
    {
        Ok(session) => {
            ssh::disconnect(&session.handle).await;
            KeyAuth::Works
        }
        Err(e) => {
            let msg = format!("{e:#}");
            // A passphrase-protected key cannot be probed unattended, and an
            // unreachable host says nothing about whether the key would work.
            if msg.contains("passphrase") || msg.contains("could not load") {
                KeyAuth::Unknown("the key needs a passphrase".into())
            } else if msg.contains("timed out") || msg.contains("could not reach") {
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
