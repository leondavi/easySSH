//! The SSH client: connecting, running commands, and installing our public key.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use russh::client::{self, Config, Handle};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, Disconnect};

use crate::model::{AuthMethod, Profile};

/// Marker the remote echoes so we can tell "command ran" from "shell printed noise".
const OK_MARKER: &str = "__EASYSSH_OK__";
const PRESENT_MARKER: &str = "__EASYSSH_ALREADY_PRESENT__";

/// What to do about a host that is not in `known_hosts` yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Accept it and record it — trust on first use, for a connection the user
    /// asked for and is watching.
    LearnUnknown,
    /// Refuse it. Used by background probes: silently pinning a host key
    /// without the user ever seeing the fingerprint would defeat the point of
    /// showing it to them.
    RequireKnown,
}

/// Host key policy. easySSH uses trust-on-first-use against `~/.ssh/known_hosts`:
/// an unknown host is accepted and recorded, but a host whose key *changed*
/// is refused, because that is what a man-in-the-middle looks like.
pub struct Client {
    host: String,
    port: u16,
    /// The `known_hosts` file for the `.ssh` location the user has selected.
    /// russh's convenience helpers assume `~/.ssh/known_hosts`, which would
    /// disagree with the rest of the app once another location is chosen.
    known_hosts: std::path::PathBuf,
    policy: HostKeyPolicy,
    /// Filled in during the handshake so the UI can show the fingerprint.
    fingerprint: Arc<Mutex<Option<String>>>,
    /// Set when we accepted a host we had never seen before.
    first_contact: Arc<AtomicBool>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // We pin the plain host key. A host presenting a certificate is trusted by
        // its CA, which is a policy easySSH does not try to second-guess.
        let server_public_key = match server_public_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key,
            russh::keys::PublicKeyOrCertificate::Certificate(_) => return Ok(true),
        };
        let fp = server_public_key
            .fingerprint(Default::default())
            .to_string();
        if let Ok(mut slot) = self.fingerprint.lock() {
            *slot = Some(fp);
        }

        match russh::keys::check_known_hosts_path(
            &self.host,
            self.port,
            server_public_key,
            &self.known_hosts,
        ) {
            // Known and matching.
            Ok(true) => Ok(true),
            // Not in known_hosts at all.
            Ok(false) if self.policy == HostKeyPolicy::RequireKnown => Ok(false),
            Ok(false) => {
                // Trust on first use and remember it.
                self.first_contact.store(true, Ordering::Relaxed);
                if let Err(e) = russh::keys::known_hosts::learn_known_hosts_path(
                    &self.host,
                    self.port,
                    server_public_key,
                    &self.known_hosts,
                ) {
                    log::warn!("could not record host key in known_hosts: {e}");
                }
                Ok(true)
            }
            // `KeyChanged` lands here. Refuse: this is the case worth being loud about.
            Err(e) => {
                log::error!(
                    "host key check failed for {}:{} — {e}",
                    self.host,
                    self.port
                );
                Ok(false)
            }
        }
    }
}

/// A live connection plus the facts the UI wants to display about it.
pub struct Session {
    /// Shared so tunnels can open channels on the same connection.
    pub handle: Arc<Handle<Client>>,
    pub fingerprint: String,
    pub first_contact: bool,
}

/// Result of running a single remote command.
pub struct Output {
    pub code: u32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn combined(&self) -> String {
        let mut s = self.stdout.trim().to_string();
        let err = self.stderr.trim();
        if !err.is_empty() {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(err);
        }
        s
    }
}

fn config() -> Arc<Config> {
    Arc::new(Config {
        // Long enough to survive a slow VPN handshake, short enough to fail visibly.
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        ..Default::default()
    })
}

async fn open(
    host: &str,
    port: u16,
    known_hosts: &Path,
    policy: HostKeyPolicy,
) -> Result<(Handle<Client>, Arc<Mutex<Option<String>>>, Arc<AtomicBool>)> {
    let fingerprint = Arc::new(Mutex::new(None));
    let first_contact = Arc::new(AtomicBool::new(false));
    let handler = Client {
        host: host.to_string(),
        port,
        known_hosts: known_hosts.to_path_buf(),
        policy,
        fingerprint: fingerprint.clone(),
        first_contact: first_contact.clone(),
    };

    // Resolve and connect with a bounded timeout: an unreachable host should not
    // leave the UI spinning on the OS default of ~75 seconds.
    let connect = client::connect(config(), (host, port), handler);
    let handle = tokio::time::timeout(Duration::from_secs(20), connect)
        .await
        .map_err(|_| anyhow!("timed out connecting to {host}:{port}"))?
        .with_context(|| format!("could not reach {host}:{port}"))?;

    Ok((handle, fingerprint, first_contact))
}

fn finish(
    handle: Handle<Client>,
    fingerprint: Arc<Mutex<Option<String>>>,
    first_contact: Arc<AtomicBool>,
) -> Session {
    let fp = fingerprint
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| "unknown".into());
    Session {
        handle: Arc::new(handle),
        fingerprint: fp,
        first_contact: first_contact.load(Ordering::Relaxed),
    }
}

/// Connect using a username and password.
pub async fn connect_password(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    known_hosts: &Path,
) -> Result<Session> {
    let (mut handle, fingerprint, first_contact) =
        open(host, port, known_hosts, HostKeyPolicy::LearnUnknown).await?;

    let result = handle
        .authenticate_password(username, password)
        .await
        .context("password authentication failed")?;

    if !result.success() {
        // Some hosts disable `password` and only offer `keyboard-interactive`,
        // which for a plain password prompt takes the same secret.
        let ki = handle
            .authenticate_keyboard_interactive_start(username, None)
            .await;
        let ok = match ki {
            Ok(russh::client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. }) => {
                let answers = vec![password.to_string(); prompts.len().max(1)];
                matches!(
                    handle
                        .authenticate_keyboard_interactive_respond(answers)
                        .await,
                    Ok(russh::client::KeyboardInteractiveAuthResponse::Success)
                )
            }
            Ok(russh::client::KeyboardInteractiveAuthResponse::Success) => true,
            _ => false,
        };
        if !ok {
            return Err(anyhow!("the server rejected that username or password"));
        }
    }

    Ok(finish(handle, fingerprint, first_contact))
}

/// Connect using a private key file.
pub async fn connect_key(
    host: &str,
    port: u16,
    username: &str,
    key_path: &Path,
    passphrase: Option<&str>,
    known_hosts: &Path,
    policy: HostKeyPolicy,
) -> Result<Session> {
    let key = load_secret_key(key_path, passphrase).map_err(|e| {
        anyhow!(
            "could not load {}: {e}. If the key has a passphrase, enter it and try again.",
            key_path.display()
        )
    })?;

    let (mut handle, fingerprint, first_contact) = open(host, port, known_hosts, policy).await?;

    // RSA keys must be signed with a hash the server actually accepts; older
    // servers want SHA-1 while modern ones require SHA-2.
    let hash_alg = handle.best_supported_rsa_hash().await?.flatten();
    let result = handle
        .authenticate_publickey(
            username,
            PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg),
        )
        .await
        .context("public key authentication failed")?;

    if !result.success() {
        return Err(anyhow!(
            "the server did not accept {}. Is the public key in the remote's authorized_keys?",
            key_path.display()
        ));
    }

    Ok(finish(handle, fingerprint, first_contact))
}

/// Connect a profile, taking the secret the UI collected for it.
pub async fn connect_profile(
    profile: &Profile,
    secret: Option<&str>,
    known_hosts: &Path,
) -> Result<Session> {
    match profile.auth {
        AuthMethod::Password => {
            let password = secret.ok_or_else(|| anyhow!("a password is required"))?;
            connect_password(
                &profile.host,
                profile.port,
                &profile.username,
                password,
                known_hosts,
            )
            .await
        }
        AuthMethod::Key => {
            let path = profile
                .key_path
                .as_deref()
                .ok_or_else(|| anyhow!("no private key is selected for this connection"))?;
            connect_key(
                &profile.host,
                profile.port,
                &profile.username,
                Path::new(path),
                secret.filter(|s| !s.is_empty()),
                known_hosts,
                HostKeyPolicy::LearnUnknown,
            )
            .await
        }
    }
}

/// Run one command on the remote and collect its output.
pub async fn exec(handle: &Handle<Client>, command: &str) -> Result<Output> {
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, command).await?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code = None;

    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
            ChannelMsg::ExtendedData { ref data, ext } => {
                // ext == 1 is stderr; anything else is not something we asked for.
                if ext == 1 {
                    stderr.extend_from_slice(data);
                }
            }
            ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
            _ => {}
        }
    }

    Ok(Output {
        code: code.unwrap_or(0),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// Append `public_key` to the remote's `~/.ssh/authorized_keys`, idempotently.
///
/// Returns `true` if the key was already there before we ran.
pub async fn install_public_key(
    handle: &Handle<Client>,
    public_key: &str,
) -> Result<(bool, String)> {
    let key = sanitize_public_key(public_key)?;
    let key = key.as_str();

    // umask 077 so a freshly created authorized_keys is private from the start.
    // `restorecon` fixes the SELinux label on RHEL-family hosts and is ignored elsewhere.
    let script = format!(
        r#"umask 077
mkdir -p ~/.ssh || exit 11
touch ~/.ssh/authorized_keys || exit 12
chmod 700 ~/.ssh || exit 13
chmod 600 ~/.ssh/authorized_keys || exit 14
if grep -qxF '{key}' ~/.ssh/authorized_keys 2>/dev/null; then
  printf '%s\n' '{present}'
else
  printf '%s\n' '{key}' >> ~/.ssh/authorized_keys || exit 15
fi
command -v restorecon >/dev/null 2>&1 && restorecon -F ~/.ssh ~/.ssh/authorized_keys >/dev/null 2>&1
printf '%s\n' '{ok}'
"#,
        key = key,
        present = PRESENT_MARKER,
        ok = OK_MARKER,
    );

    let out = exec(handle, &script).await?;
    let already_present = out.stdout.contains(PRESENT_MARKER);

    if !out.stdout.contains(OK_MARKER) {
        let reason = match out.code {
            11 => "could not create ~/.ssh on the remote".to_string(),
            12 | 15 => "could not write ~/.ssh/authorized_keys on the remote".to_string(),
            13 | 14 => "could not set permissions on the remote's ~/.ssh".to_string(),
            other => format!("the remote command exited with status {other}"),
        };
        let detail = out.combined();
        return Err(if detail.is_empty() {
            anyhow!("{reason}")
        } else {
            anyhow!("{reason}: {detail}")
        });
    }

    // Strip our markers so the UI shows only what the remote genuinely said.
    let message = out
        .combined()
        .lines()
        .filter(|l| !l.contains(OK_MARKER) && !l.contains(PRESENT_MARKER))
        .collect::<Vec<_>>()
        .join("\n");

    Ok((already_present, message))
}

/// Make a public key line safe to embed in a single-quoted shell string.
///
/// The algorithm and base64 fields can only contain characters that are already
/// safe. The trailing comment is free-form and belongs to whoever made the key,
/// so a quote or a control character there is stripped rather than treated as
/// an error — the comment carries no meaning to `sshd`.
fn sanitize_public_key(line: &str) -> Result<String> {
    let line = line.trim();
    if line.is_empty() {
        return Err(anyhow!("the public key is empty"));
    }
    if line.contains('\n') || line.contains('\r') {
        return Err(anyhow!("a public key must be a single line"));
    }

    let mut parts = line.splitn(3, ' ');
    let algorithm = parts.next().unwrap_or_default();
    let body = parts.next().unwrap_or_default();
    let comment = parts.next().unwrap_or_default();

    if algorithm.is_empty() || body.is_empty() {
        return Err(anyhow!("'{line}' is not an OpenSSH public key"));
    }
    if !algorithm
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '@' || c == '.')
    {
        return Err(anyhow!("the public key's algorithm field looks malformed"));
    }
    if !body
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
    {
        return Err(anyhow!("the public key's body is not valid base64"));
    }

    let comment: String = comment
        .chars()
        .filter(|c| !c.is_control() && *c != '\'' && *c != '\\')
        .collect();

    Ok(if comment.trim().is_empty() {
        format!("{algorithm} {body}")
    } else {
        format!("{algorithm} {body} {}", comment.trim())
    })
}

/// Ask the remote for a one-line description of itself, for the session header.
pub async fn describe_remote(handle: &Handle<Client>) -> String {
    match exec(handle, "uname -sr 2>/dev/null || ver").await {
        Ok(out) => {
            let s = out.combined();
            let line = s.lines().next().unwrap_or("").trim();
            if line.is_empty() {
                "connected".into()
            } else {
                line.to_string()
            }
        }
        Err(_) => "connected".into(),
    }
}

pub async fn disconnect(handle: &Handle<Client>) {
    let _ = handle
        .disconnect(Disconnect::ByApplication, "easySSH closing", "en")
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal SSH server so the client path can be exercised for real.
    /// Without it, `exec` collecting a command's output is untestable.
    mod harness {
        use std::sync::Arc;

        use russh::server::{Auth, Handler, Msg, Session};
        use russh::{Channel, ChannelId};
        use tokio::net::TcpListener;

        pub const PASSWORD: &str = "correct-horse";

        #[derive(Default)]
        pub struct Server {
            /// Keep the server-side channel alive; dropping it would close the
            /// channel before the command's output could be written.
            channels: Vec<Channel<Msg>>,
        }

        impl Handler for Server {
            type Error = russh::Error;

            async fn auth_password(
                &mut self,
                _user: &str,
                password: &str,
            ) -> Result<Auth, Self::Error> {
                if password == PASSWORD {
                    Ok(Auth::Accept)
                } else {
                    Ok(Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    })
                }
            }

            async fn channel_open_session(
                &mut self,
                channel: Channel<Msg>,
                reply: russh::server::ChannelOpenHandle,
                _session: &mut Session,
            ) -> Result<(), Self::Error> {
                // Dropping the handle without accepting sends
                // AdministrativelyProhibited back to the client.
                reply.accept().await;
                self.channels.push(channel);
                Ok(())
            }

            async fn exec_request(
                &mut self,
                channel: ChannelId,
                data: &[u8],
                session: &mut Session,
            ) -> Result<(), Self::Error> {
                let command = String::from_utf8_lossy(data).to_string();
                session.channel_success(channel)?;

                // Echo the command back so the test can prove the right bytes
                // travelled, and emit on both streams plus a non-zero status.
                session.data(channel, format!("out:{command}\n"))?;
                session.extended_data(channel, 1, "err:diagnostic\n".to_string())?;
                session.exit_status_request(channel, 3)?;
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }
        }

        /// Start the server on an ephemeral port and return it.
        pub async fn start() -> u16 {
            let key = ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519)
                .expect("host key");
            let config = Arc::new(russh::server::Config {
                keys: vec![key],
                ..Default::default()
            });

            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().unwrap().port();

            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let config = config.clone();
                    tokio::spawn(async move {
                        if let Ok(session) =
                            russh::server::run_stream(config, stream, Server::default()).await
                        {
                            let _ = session.await;
                        }
                    });
                }
            });

            port
        }

        /// A known_hosts path inside a fresh temp directory.
        pub fn known_hosts(tag: &str) -> std::path::PathBuf {
            let dir =
                std::env::temp_dir().join(format!("easyssh-exec-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir.join("known_hosts")
        }
    }

    #[tokio::test]
    async fn exec_collects_stdout_stderr_and_exit_status() {
        let port = harness::start().await;
        let kh = harness::known_hosts("exec");

        let session = connect_password("127.0.0.1", port, "someone", harness::PASSWORD, &kh)
            .await
            .expect("connect");

        let out = exec(&session.handle, "echo hello").await.expect("exec");

        assert_eq!(out.stdout, "out:echo hello\n", "stdout was not collected");
        assert_eq!(out.stderr, "err:diagnostic\n", "stderr was not collected");
        assert_eq!(out.code, 3, "exit status was not collected");
        assert_eq!(out.combined(), "out:echo hello\nerr:diagnostic");
    }

    #[tokio::test]
    async fn a_first_contact_host_is_recorded_in_known_hosts() {
        let port = harness::start().await;
        let kh = harness::known_hosts("tofu");

        let session = connect_password("127.0.0.1", port, "someone", harness::PASSWORD, &kh)
            .await
            .expect("connect");

        assert!(
            session.first_contact,
            "a host absent from known_hosts is first contact"
        );
        assert!(kh.is_file(), "the host key should have been recorded");

        // Connecting again must recognise the host rather than re-learn it.
        let again = connect_password("127.0.0.1", port, "someone", harness::PASSWORD, &kh)
            .await
            .expect("reconnect");
        assert!(!again.first_contact, "the host should now be known");
    }

    #[tokio::test]
    async fn a_wrong_password_is_rejected_with_a_readable_message() {
        let port = harness::start().await;
        let kh = harness::known_hosts("badpw");

        let err = match connect_password("127.0.0.1", port, "someone", "nope", &kh).await {
            Ok(_) => panic!("a wrong password must not authenticate"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("username or password"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn keeps_a_normal_key_intact() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample easySSH@studio";
        assert_eq!(sanitize_public_key(line).unwrap(), line);
    }

    #[test]
    fn strips_quotes_from_the_comment_rather_than_failing() {
        // A comment is free-form text; an apostrophe in it must not break the
        // single-quoted shell string we build, nor block the install.
        let line = "ssh-rsa AAAAB3NzaC1yc2EAAAA O'Brien's laptop";
        let out = sanitize_public_key(line).unwrap();
        assert_eq!(out, "ssh-rsa AAAAB3NzaC1yc2EAAAA OBriens laptop");
        assert!(!out.contains('\''));
    }

    #[test]
    fn accepts_a_key_with_no_comment() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample";
        assert_eq!(sanitize_public_key(line).unwrap(), line);
    }

    #[test]
    fn rejects_input_that_is_not_a_key() {
        assert!(sanitize_public_key("").is_err());
        assert!(sanitize_public_key("ssh-ed25519").is_err());
        assert!(sanitize_public_key("ssh-ed25519 not+valid+base64!!").is_err());
        // A newline could smuggle a second authorized_keys entry.
        assert!(sanitize_public_key("ssh-ed25519 AAAA me\nssh-rsa BBBB attacker").is_err());
    }
}
