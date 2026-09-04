//! Local port forwarding: `127.0.0.1:local_port` -> `remote_host:remote_port`,
//! where `remote_host` is resolved from the *remote* machine's network.
//!
//! This is what lets you open a web app that only listens on the server's
//! loopback interface, or on a box reachable only from the server, as if it
//! were running here.

use std::sync::atomic::{AtomicU64, Ordering};
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
}

impl RunningTunnel {
    pub fn stop(self) {
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
    let bind = format!("127.0.0.1:{}", spec.local_port);
    let listener = TcpListener::bind(&bind).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow!(
                "port {} is already in use on this machine — pick another local port",
                spec.local_port
            )
        } else {
            anyhow!("could not listen on {bind}: {e}")
        }
    })?;

    let connections = Arc::new(AtomicU64::new(0));
    let counter = connections.clone();
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
                    if msg.contains("Connection refused") || msg.contains("administratively") {
                        on_error(format!(
                            "the remote refused {remote_host}:{remote_port} — is the service running there?"
                        ));
                    }
                }
            });
        }
    });

    Ok(RunningTunnel { connections, task })
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
