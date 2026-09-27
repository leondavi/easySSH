//! Local port forwarding: `127.0.0.1:local_port` -> `remote_host:remote_port`,
//! where `remote_host` is resolved from the *remote* machine's network.
//!
//! This is what lets you open a web app that only listens on the server's
//! loopback interface, or on a box reachable only from the server, as if it
//! were running here.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use russh::client::Handle;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::model::Tunnel;
use crate::ssh::Client;

/// A running forward. Dropping this does not stop it; call `stop`.
pub struct RunningTunnel {
    pub connections: Arc<AtomicU64>,
    task: JoinHandle<()>,
    /// Cleared by `stop`. Connections already in flight keep running on their
    /// own tasks after the accept loop is aborted, and when they finally fail
    /// — often because the very session this tunnel was replaced for is dead —
    /// their errors must not be pinned on the forward that replaced it.
    active: Arc<AtomicBool>,
}

impl RunningTunnel {
    pub fn stop(self) {
        self.active.store(false, Ordering::Relaxed);
        self.task.abort();
    }

    pub fn is_alive(&self) -> bool {
        !self.task.is_finished()
    }
}

/// Bind the local port and start accepting. Fails fast if the port is taken,
/// so the UI can say so instead of silently doing nothing.
pub async fn start(
    handle: Arc<Handle<Client>>,
    spec: Tunnel,
    on_error: impl Fn(String) + Send + Sync + 'static,
) -> Result<RunningTunnel> {
    start_counting(handle, spec, Arc::new(AtomicU64::new(0)), on_error).await
}

/// As `start`, but carrying an existing connection counter forward.
///
/// Used when a forward is rebuilt after its session dropped: the tunnel is new
/// but the user's traffic through that port is not, and a count that jumped
/// back to zero would read as "nothing has ever connected" at exactly the
/// moment they are trying to work out what just happened.
pub async fn start_counting(
    handle: Arc<Handle<Client>>,
    spec: Tunnel,
    connections: Arc<AtomicU64>,
    on_error: impl Fn(String) + Send + Sync + 'static,
) -> Result<RunningTunnel> {
    let bind = format!("127.0.0.1:{}", spec.local_port);
    let listener = TcpListener::bind(&bind).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            // Naming the likely culprit matters: the commonest holder of this
            // port is an `ssh -L` session easySSH opened for the terminal,
            // which means the forward is already working and telling the user
            // to pick another port sends them the wrong way entirely.
            anyhow!(
                "{bind} is already in use on this machine. If you opened a terminal \
                 for this connection with its tunnels included, that ssh session is \
                 already forwarding this port — {} works as it is. Otherwise close \
                 whatever holds the port, or give this tunnel a different local port.",
                spec.local_url()
            )
        } else {
            anyhow!("could not listen on {bind}: {e}")
        }
    })?;

    let counter = connections.clone();
    let active = Arc::new(AtomicBool::new(true));
    let live = active.clone();
    let remote_host = spec.remote_host.clone();
    let remote_port = spec.remote_port;
    let on_error = Arc::new(on_error);

    let task = tokio::spawn(async move {
        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    on_error(format!("stopped accepting connections: {e}"));
                    return;
                }
            };
            counter.fetch_add(1, Ordering::Relaxed);

            let handle = handle.clone();
            let remote_host = remote_host.clone();
            let on_error = on_error.clone();
            let live = live.clone();
            // One task per connection: a browser opens several at once and a
            // slow response on one must not block the others.
            tokio::spawn(async move {
                let originator = peer.ip().to_string();
                if let Err(e) = forward(
                    handle,
                    socket,
                    &remote_host,
                    remote_port,
                    &originator,
                    peer.port(),
                )
                .await
                {
                    // A browser closing a keep-alive socket is normal, not worth surfacing.
                    log::debug!("forwarded connection ended: {e:#}");
                    let msg = e.to_string();
                    let still_ours = live.load(Ordering::Relaxed);
                    if still_ours
                        && (msg.contains("Connection refused") || msg.contains("administratively"))
                    {
                        on_error(format!(
                            "the remote refused {remote_host}:{remote_port} — is the service running there?"
                        ));
                    }
                }
            });
        }
    });

    Ok(RunningTunnel {
        connections,
        task,
        active,
    })
}

async fn forward(
    handle: Arc<Handle<Client>>,
    mut socket: TcpStream,
    remote_host: &str,
    remote_port: u16,
    originator_ip: &str,
    originator_port: u16,
) -> Result<()> {
    let channel = handle
        .channel_open_direct_tcpip(
            remote_host,
            remote_port as u32,
            originator_ip,
            originator_port as u32,
        )
        .await
        .with_context(|| format!("opening a channel to {remote_host}:{remote_port}"))?;

    let mut stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut socket, &mut stream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testserver as harness;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn spec(local_port: u16, remote_host: &str, remote_port: u16) -> Tunnel {
        Tunnel {
            id: "t1".into(),
            name: "Test".into(),
            local_port,
            remote_host: remote_host.into(),
            remote_port,
            auto_start: false,
            scheme: "http".into(),
        }
    }

    /// Ask the OS for a free port by binding and immediately releasing it.
    async fn free_port() -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    }

    async fn connect_test_server(tag: &str) -> Arc<russh::client::Handle<crate::ssh::Client>> {
        let port = harness::start().await;
        let kh = harness::known_hosts(tag);
        let session =
            crate::ssh::connect_password("127.0.0.1", port, "someone", harness::PASSWORD, &kh)
                .await
                .expect("connect");
        session.handle
    }

    #[tokio::test]
    async fn forwards_bytes_to_the_requested_remote_address() {
        let handle = connect_test_server("tunnel-fwd").await;
        let local = free_port().await;

        let running = start(handle, spec(local, "10.0.0.9", 8443), |_| {})
            .await
            .expect("tunnel should bind");

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", local))
            .await
            .expect("connect through the tunnel");

        // The server announces the address it was asked to reach, which proves
        // the remote side of the forward is resolved remotely and not here.
        let mut buf = vec![0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&buf[..n]).trim(),
            "target=10.0.0.9:8443"
        );

        // And the channel carries data both ways.
        client.write_all(b"ping").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");

        assert_eq!(running.connections.load(Ordering::Relaxed), 1);
        assert!(running.is_alive());
        running.stop();
    }

    #[tokio::test]
    async fn a_taken_local_port_is_reported_not_silently_ignored() {
        let handle = connect_test_server("tunnel-busy").await;

        // Hold the port so the tunnel cannot have it.
        let squatter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let taken = squatter.local_addr().unwrap().port();

        let err = match start(handle, spec(taken, "localhost", 80), |_| {}).await {
            Ok(_) => panic!("binding a port already in use must fail"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("already in use") && err.contains(&taken.to_string()),
            "unhelpful error: {err}"
        );
    }

    /// The bug the tunnel supervisor exists for, pinned down.
    ///
    /// A forward whose SSH session has silently stopped relaying still binds its
    /// port, still accepts connections, and still reports itself alive — and
    /// carries nothing. Nothing about the tunnel itself can tell you it is
    /// broken, which is why health has to be asked of the session instead.
    #[tokio::test]
    async fn a_forward_looks_alive_after_its_session_goes_silent() {
        use tokio::io::AsyncReadExt;

        let net = crate::testserver::start_cuttable().await;
        let kh = harness::known_hosts("tunnel-silent");
        let session =
            crate::ssh::connect_password("127.0.0.1", net.port, "someone", harness::PASSWORD, &kh)
                .await
                .expect("connect");
        let handle = session.handle.clone();
        let local = free_port().await;

        let running = start(handle.clone(), spec(local, "10.0.0.9", 8443), |_| {})
            .await
            .expect("bind");

        // Working to begin with: the server announces the address it was asked for.
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", local))
            .await
            .expect("connect through the tunnel");
        let mut buf = vec![0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&buf[..n]).trim(),
            "target=10.0.0.9:8443"
        );

        net.blackhole();

        // The local half is entirely unaffected — this is the trap.
        assert!(
            running.is_alive(),
            "the accept loop survives its session dying, which is the whole problem"
        );
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", local))
            .await
            .expect("the port still accepts connections after the session died");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(600), client.read(&mut buf))
                .await
                .is_err(),
            "a forward over a dead session should carry nothing — if this ever \
             starts passing data, the premise of restore.rs has changed"
        );

        // So the only reliable signal is the session's own health.
        assert!(
            !crate::ssh::healthy_within(&handle, std::time::Duration::from_millis(600)).await,
            "the session health probe is what has to catch this"
        );

        running.stop();
    }

    /// A rebuilt forward must not look like a port nothing has ever used: the
    /// count is the user's evidence that traffic is flowing.
    #[tokio::test]
    async fn a_rebuilt_tunnel_carries_its_connection_count_forward() {
        let handle = connect_test_server("tunnel-recount").await;
        let local = free_port().await;
        let counter = Arc::new(AtomicU64::new(0));

        let first = start_counting(
            handle.clone(),
            spec(local, "localhost", 80),
            counter.clone(),
            |_| {},
        )
        .await
        .expect("bind");
        let _ = tokio::net::TcpStream::connect(("127.0.0.1", local))
            .await
            .expect("connect through the tunnel");

        // Wait for the accept loop to register it.
        for _ in 0..50 {
            if counter.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        first.stop();

        // Rebuild on the same counter, as the supervisor does.
        for _ in 0..50 {
            match start_counting(
                handle.clone(),
                spec(local, "localhost", 80),
                counter.clone(),
                |_| {},
            )
            .await
            {
                Ok(second) => {
                    assert_eq!(
                        second.connections.load(Ordering::Relaxed),
                        1,
                        "the rebuilt tunnel reset the count to zero"
                    );
                    second.stop();
                    return;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }
        panic!("the local port never became free again");
    }

    #[tokio::test]
    async fn stopping_a_tunnel_frees_its_local_port() {
        let handle = connect_test_server("tunnel-stop").await;
        let local = free_port().await;

        let running = start(handle.clone(), spec(local, "localhost", 80), |_| {})
            .await
            .expect("bind");
        running.stop();

        // The abort is asynchronous, so give the listener a moment to drop.
        for _ in 0..50 {
            if tokio::net::TcpListener::bind(("127.0.0.1", local))
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the local port was still bound after the tunnel stopped");
    }
}
