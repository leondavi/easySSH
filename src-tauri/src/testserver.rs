//! A real SSH server for tests.
//!
//! Without one, the parts of easySSH that matter most — authenticating, running
//! the authorized_keys script, forwarding a port — could only be verified by
//! reading them. This server is small enough to be obviously correct and lets
//! the client be driven end to end.

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
    /// When set, exec requests really run under `sh` with `HOME` bound
    /// to this directory instead of being echoed.
    shell: Option<std::path::PathBuf>,
    /// The one public key this server lets in, standing in for its
    /// `authorized_keys`. `None` refuses every key.
    accept_key: Option<ssh_key::PublicKey>,
}

impl Handler for Server {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        if password == PASSWORD {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let trusted = self
            .accept_key
            .as_ref()
            .is_some_and(|k| k.key_data() == public_key.key_data());
        Ok(if trusted {
            Auth::Accept
        } else {
            Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }
        })
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

        match &self.shell {
            // Run the command for real, with HOME pointed at a
            // throwaway directory. This is what lets the
            // authorized_keys script be tested as a script rather than
            // as a string we hope is correct.
            Some(home) => {
                let out = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&command)
                    .env("HOME", home)
                    .output()
                    .expect("run shell");
                if !out.stdout.is_empty() {
                    session.data(channel, out.stdout)?;
                }
                if !out.stderr.is_empty() {
                    session.extended_data(channel, 1, out.stderr)?;
                }
                session.exit_status_request(channel, out.status.code().unwrap_or(0) as u32)?;
            }
            // Otherwise echo, so the test can prove the right bytes
            // travelled, on both streams plus a non-zero status.
            None => {
                session.data(channel, format!("out:{command}\n"))?;
                session.extended_data(channel, 1, "err:diagnostic\n".to_string())?;
                session.exit_status_request(channel, 3)?;
            }
        }

        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    /// Accept a forwarded channel and echo whatever is written to it,
    /// so a tunnel can be driven end to end.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;

        let target = format!("{host_to_connect}:{port_to_connect}");
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = channel.into_stream();
            // Announce the address we were asked for, so the test can
            // prove the remote side of the forward is what was
            // requested, then echo the client's bytes back.
            let _ = stream
                .write_all(format!("target={target}\n").as_bytes())
                .await;
            let mut buf = vec![0u8; 1024];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        Ok(())
    }
}

/// Start an echoing server on an ephemeral port.
pub async fn start() -> u16 {
    start_with(None).await
}

/// A server that trusts exactly one public key, and counts the connections
/// made to it — so a test can prove a set of keys was offered over one.
pub struct KeyServer {
    pub port: u16,
    pub connections: Arc<std::sync::atomic::AtomicUsize>,
}

pub async fn start_trusting(key: ssh_key::PublicKey) -> KeyServer {
    let host_key = ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519)
        .expect("host key");
    let config = Arc::new(russh::server::Config {
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let connections: Arc<std::sync::atomic::AtomicUsize> = Arc::default();
    let count = connections.clone();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let config = config.clone();
            let key = key.clone();
            tokio::spawn(async move {
                let handler = Server {
                    accept_key: Some(key),
                    ..Default::default()
                };
                if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });

    KeyServer { port, connections }
}

/// A test server reached through a proxy the test can cut, so a connected
/// client can lose its transport the way it does in the wild.
///
/// Aborting the server's own task is not enough: russh drives a session on an
/// internal task of its own, so the session survives and keeps answering. Only
/// interfering with the bytes on the wire reproduces the real failure.
pub struct Cuttable {
    /// The port the client should connect to.
    pub port: u16,
    /// The server itself, bypassing the proxy — a route that still works
    /// after the proxied one has been cut, as a reconnect finds once the
    /// network is back.
    pub upstream: u16,
    proxy: tokio::task::JoinHandle<()>,
    /// Every relay the proxy has spawned, so `cut` can drop their sockets. The
    /// accept loop alone is not enough: aborting it stops new connections and
    /// leaves the established one relaying happily.
    relays: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>>,
    /// Set to stop relaying while both sockets stay open.
    silence: tokio::sync::watch::Sender<bool>,
}

impl Cuttable {
    /// Drop the sockets, so the client is reset — a server restart, or a
    /// firewall that answers.
    pub fn cut(&self) {
        self.proxy.abort();
        if let Ok(relays) = self.relays.lock() {
            for r in relays.iter() {
                r.abort();
            }
        }
    }

    /// Keep the sockets open and relay nothing at all.
    ///
    /// This is the failure that made easySSH's tunnels go quietly useless: the
    /// laptop slept, or a NAT table forgot the flow, and neither end is told.
    /// russh notices nothing, the local listener keeps accepting, and every
    /// channel opened on the session hangs instead of failing.
    pub fn blackhole(&self) {
        let _ = self.silence.send(true);
    }
}

/// Start an echoing server behind a proxy that `Cuttable` can interfere with.
pub async fn start_cuttable() -> Cuttable {
    let upstream = start().await;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let port = listener.local_addr().unwrap().port();
    let (silence, rx) = tokio::sync::watch::channel(false);
    let relays: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
    let registry = relays.clone();

    let proxy = tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let Ok(server) = tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await else {
                return;
            };
            let task = tokio::spawn(relay(client, server, rx.clone()));
            if let Ok(mut open) = registry.lock() {
                open.push(task.abort_handle());
            }
        }
    });

    Cuttable {
        port,
        upstream,
        proxy,
        relays,
        silence,
    }
}

/// Copy bytes both ways until either side closes, or the test asks for silence.
async fn relay(
    mut client: tokio::net::TcpStream,
    mut server: tokio::net::TcpStream,
    mut silence: tokio::sync::watch::Receiver<bool>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut from_client = vec![0u8; 8192];
    let mut from_server = vec![0u8; 8192];

    loop {
        tokio::select! {
            _ = silence.changed() => {}
            r = client.read(&mut from_client) => match r {
                Ok(0) | Err(_) => return,
                Ok(n) => if server.write_all(&from_client[..n]).await.is_err() { return },
            },
            r = server.read(&mut from_server) => match r {
                Ok(0) | Err(_) => return,
                Ok(n) => if client.write_all(&from_server[..n]).await.is_err() { return },
            },
        }

        if *silence.borrow() {
            // Hold both sockets open forever and forward nothing. Returning
            // here would close them, which is the failure we are *not*
            // reproducing.
            std::future::pending::<()>().await;
        }
    }
}

/// Start a server that executes commands for real, with `HOME` bound to
/// a sandbox directory.
///
/// Unix only: it shells out to `sh`, and the tests that use it check POSIX
/// file modes. Without the gate it is dead code on Windows, which `clippy
/// -D warnings` rightly refuses.
#[cfg(unix)]
pub async fn start_with_shell(home: std::path::PathBuf) -> u16 {
    start_with(Some(home)).await
}

async fn start_with(shell: Option<std::path::PathBuf>) -> u16 {
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
            let shell = shell.clone();
            tokio::spawn(async move {
                let handler = Server {
                    shell: shell.clone(),
                    ..Default::default()
                };
                if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });

    port
}

/// A known_hosts path inside a fresh temp directory.
pub fn known_hosts(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("easyssh-exec-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("known_hosts")
}
