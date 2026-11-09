//! Local port forwarding: `127.0.0.1:local_port` -> `remote_host:remote_port`,
//! where `remote_host` is resolved from the *remote* machine's network.
//!
//! This is what lets you open a web app that only listens on the server's
//! loopback interface, or on a box reachable only from the server, as if it
//! were running here.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use russh::client::Handle;
use tokio::net::TcpListener;
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

    let breaker = Arc::new(Breaker::default());

    let task = tokio::spawn(async move {
        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(v) => v,
                // Out of file descriptors (a GUI app on macOS gets 256 by
                // default, and a browser opens many), or a client that gave
                // up mid-handshake: both pass. Ending the loop over them would
                // take the tunnel down until the next health sweep.
                Err(e) if is_transient_accept_error(&e) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => {
                    on_error(format!("stopped accepting connections: {e}"));
                    return;
                }
            };

            // While the target keeps refusing, close the client here rather
            // than asking the server to try again: a page or script that
            // retries the moment it fails would otherwise turn into a stream
            // of channel opens over the SSH link, and of connection attempts
            // from the server to the target.
            if !breaker.admit(Instant::now()) {
                drop(socket);
                continue;
            }
            counter.fetch_add(1, Ordering::Relaxed);

            let handle = handle.clone();
            let remote_host = remote_host.clone();
            let on_error = on_error.clone();
            let live = live.clone();
            let breaker = breaker.clone();
            // One task per connection: a browser opens several at once and a
            // slow response on one must not block the others.
            tokio::spawn(async move {
                let originator = peer.ip().to_string();
                let channel = match handle
                    .channel_open_direct_tcpip(
                        remote_host.as_str(),
                        remote_port as u32,
                        originator.as_str(),
                        peer.port() as u32,
                    )
                    .await
                {
                    Ok(channel) => {
                        breaker.succeeded();
                        channel
                    }
                    Err(e) => {
                        log::debug!("opening a channel to {remote_host}:{remote_port}: {e:#}");
                        let failed = breaker.failed(Instant::now());
                        if !live.load(Ordering::Relaxed) {
                            return;
                        }
                        let msg = e.to_string();
                        let refused =
                            msg.contains("Connection refused") || msg.contains("administratively");
                        // One message per streak of failures, and one when
                        // new connections are first held back — not one per
                        // attempt, which would bury the user in toasts.
                        match failed {
                            Failed::First if refused => on_error(format!(
                                "the remote refused {remote_host}:{remote_port} — is the service running there?"
                            )),
                            Failed::FirstPause(pause) => on_error(format!(
                                "{remote_host}:{remote_port} keeps failing on the remote side — \
                                 holding back new connections, retrying every {}s at most",
                                pause.as_secs().max(1)
                            )),
                            _ => {}
                        }
                        return;
                    }
                };
                let mut stream = channel.into_stream();
                let mut socket = socket;
                if let Err(e) = tokio::io::copy_bidirectional(&mut socket, &mut stream).await {
                    // A browser closing a keep-alive socket is normal, not worth surfacing.
                    log::debug!("forwarded connection ended: {e:#}");
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

/// Consecutive channel-open failures before new connections are held back.
/// A few are allowed through because a browser opens several at once, and
/// one refused burst says little on its own.
const TRIP_AFTER: u32 = 3;
const FIRST_PAUSE: Duration = Duration::from_secs(1);
const LONGEST_PAUSE: Duration = Duration::from_secs(30);

/// A circuit breaker over a forward's channel opens.
///
/// Once the target has refused `TRIP_AFTER` times in a row, connections are
/// closed locally for a pause that doubles each time the target is still
/// failing, up to `LONGEST_PAUSE`. When a pause ends exactly one connection is
/// let through to find out; its success closes the breaker again.
#[derive(Default)]
struct Breaker(std::sync::Mutex<BreakerState>);

#[derive(Default)]
struct BreakerState {
    failures: u32,
    /// Pauses in the current streak, which set the length of the next one.
    pauses: u32,
    paused_until: Option<Instant>,
    /// A connection is out testing whether the target is back.
    probing: bool,
}

#[derive(Debug, PartialEq)]
enum Failed {
    /// The first failure since the last success.
    First,
    /// The failure that first held new connections back, and for how long.
    FirstPause(Duration),
    Again,
}

impl Breaker {
    fn state(&self) -> std::sync::MutexGuard<'_, BreakerState> {
        // Nothing panics while holding it, but a poisoned breaker must not
        // take the tunnel down with it.
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether a new connection may open a channel.
    fn admit(&self, now: Instant) -> bool {
        let mut s = self.state();
        if s.failures < TRIP_AFTER {
            return true;
        }
        if s.probing || s.paused_until.is_some_and(|until| now < until) {
            return false;
        }
        s.probing = true;
        true
    }

    fn succeeded(&self) {
        *self.state() = BreakerState::default();
    }

    fn failed(&self, now: Instant) -> Failed {
        let mut s = self.state();
        s.failures += 1;
        s.probing = false;
        if s.failures < TRIP_AFTER {
            return if s.failures == 1 {
                Failed::First
            } else {
                Failed::Again
            };
        }
        // Failures from connections admitted before the pause began land
        // during it, and must not stretch it further.
        if s.paused_until.is_some_and(|until| now < until) {
            return Failed::Again;
        }
        let pause = (FIRST_PAUSE * 2u32.saturating_pow(s.pauses.min(8))).min(LONGEST_PAUSE);
        s.pauses += 1;
        s.paused_until = Some(now + pause);
        if s.pauses == 1 {
            Failed::FirstPause(pause)
        } else {
            Failed::Again
        }
    }
}

/// Accept errors that say nothing about the listener itself.
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    if matches!(
        e.kind(),
        ConnectionAborted | ConnectionReset | Interrupted | WouldBlock
    ) {
        return true;
    }
    // ENOMEM, ENFILE, EMFILE (too many open files), ENOBUFS — the last
    // differs by platform.
    const ENOBUFS: i32 = if cfg!(target_os = "linux") { 105 } else { 55 };
    match e.raw_os_error() {
        Some(code) if cfg!(unix) => matches!(code, 12 | 23 | 24) || code == ENOBUFS,
        Some(code) if cfg!(windows) => matches!(code, 10024 | 10055), // WSAEMFILE, WSAENOBUFS
        _ => false,
    }
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

    #[test]
    fn the_breaker_lets_a_burst_through_then_pauses_and_probes() {
        let b = Breaker::default();
        let t0 = Instant::now();

        for _ in 0..TRIP_AFTER {
            assert!(b.admit(t0));
        }
        assert_eq!(b.failed(t0), Failed::First);
        assert_eq!(b.failed(t0), Failed::Again);
        assert_eq!(b.failed(t0), Failed::FirstPause(FIRST_PAUSE));

        // Held back for the pause, and a straggler from before it does not
        // stretch it.
        assert!(!b.admit(t0));
        assert_eq!(b.failed(t0), Failed::Again);
        assert!(!b.admit(t0 + FIRST_PAUSE / 2));

        // Then exactly one probe.
        let t1 = t0 + FIRST_PAUSE;
        assert!(b.admit(t1));
        assert!(!b.admit(t1), "only one connection probes at a time");

        // Failing again doubles the pause.
        b.failed(t1);
        assert!(!b.admit(t1 + FIRST_PAUSE));
        assert!(b.admit(t1 + FIRST_PAUSE * 2));

        // A success closes it entirely.
        b.succeeded();
        assert!(b.admit(t1) && b.admit(t1) && b.admit(t1));
    }

    #[test]
    fn the_breaker_pause_is_capped() {
        let b = Breaker::default();
        let mut now = Instant::now();
        for _ in 0..40 {
            b.failed(now);
            now += LONGEST_PAUSE;
        }
        b.failed(now);
        assert!(!b.admit(now + LONGEST_PAUSE - Duration::from_millis(1)));
        assert!(b.admit(now + LONGEST_PAUSE));
    }

    /// The failure that prompted the breaker: a client retrying against a
    /// target that is down must not turn into a channel open per attempt.
    #[tokio::test]
    async fn a_refusing_target_is_not_hammered() {
        let handle = connect_test_server("tunnel-refused").await;
        let local = free_port().await;
        let errors = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen = errors.clone();

        let running = start(handle, spec(local, harness::REFUSED_HOST, 80), move |e| {
            seen.lock().unwrap().push(e)
        })
        .await
        .expect("bind");

        // A client reconnecting the moment it is dropped, for half a second.
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut attempts = 0;
        while Instant::now() < deadline {
            if let Ok(mut c) = tokio::net::TcpStream::connect(("127.0.0.1", local)).await {
                let mut buf = [0u8; 16];
                let _ = c.read(&mut buf).await;
            }
            attempts += 1;
        }

        let opened = running.connections.load(Ordering::Relaxed);
        assert!(attempts > 20, "the client barely ran: {attempts}");
        assert!(
            opened <= TRIP_AFTER as u64 + 1,
            "{opened} channel opens for {attempts} attempts — the breaker did not hold"
        );
        let errors = errors.lock().unwrap().clone();
        assert!(errors.len() <= 2, "one toast per attempt: {errors:?}");
        running.stop();
    }
}
