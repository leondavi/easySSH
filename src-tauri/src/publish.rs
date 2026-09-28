//! Publishing one local file or folder to a server, as a plain URL.
//!
//! The point is to hand something on this machine to a program running on the
//! server — typically an agent — without copying it there first: the server
//! just fetches `http://127.0.0.1:<port>/<token>/<name>`.
//!
//! # How the URL reaches this machine
//!
//! Nothing listens on this machine's network. Instead easySSH asks the *server*
//! to listen on its own loopback interface (an SSH remote forward, `ssh -R`)
//! and to send each connection back down the SSH session that is already open.
//! Those connections are answered here, directly on the SSH channel. So:
//!
//! * it works from behind NAT and firewalls, because the session is outbound;
//! * nothing on this machine's LAN can reach the file, loopback included;
//! * on the server, only local processes can — `127.0.0.1`, not `0.0.0.0`.
//!
//! # The token
//!
//! Anyone on the server who knows the URL can fetch the file, so the URL
//! carries a random token that is replaced every fifteen minutes. A link that
//! has been pasted somewhere stops working on its own; the app shows the
//! current one.
//!
//! The HTTP here is deliberately tiny: `GET` and `HEAD`, one request per
//! connection, no keep-alive. That is all `curl`, `wget` and an agent's HTTP
//! client need, and there is very little of it to get wrong.

use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// How long one token stays valid.
pub const TOKEN_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// The longest request head accepted. A `GET` line and a few headers fit many
/// times over; anything bigger is not a client we want to talk to.
const MAX_HEAD: usize = 16 * 1024;

/// Most entries listed for a folder, so a published home directory cannot make
/// one request walk the whole disk.
const MAX_LISTED: usize = 10_000;

/// A token and when it stops working.
#[derive(Debug, Clone)]
struct Token {
    value: String,
    expires: Instant,
    /// The same moment as wall-clock seconds, for the UI's countdown.
    expires_unix: u64,
}

impl Token {
    fn fresh() -> Self {
        use rand::RngExt;
        let bytes: [u8; 16] = rand::rng().random();
        Self {
            value: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            expires: Instant::now() + TOKEN_LIFETIME,
            expires_unix: crate::store::now() + TOKEN_LIFETIME.as_secs(),
        }
    }
}

/// The one thing a connection is publishing.
pub struct Shared {
    pub path: PathBuf,
    /// The name it is served under — the file or folder's own name.
    pub name: String,
    pub is_dir: bool,
    token: Mutex<Token>,
}

impl Shared {
    pub fn new(path: &Path) -> Result<Self> {
        let meta = std::fs::metadata(path).map_err(|e| anyhow!("{}: {e}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .filter(|n| !n.is_empty())
            .ok_or_else(|| anyhow!("{} cannot be published: it has no name", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            name,
            is_dir: meta.is_dir(),
            token: Mutex::new(Token::fresh()),
        })
    }

    /// The token in force now, replacing it first if it has run out. Rotation
    /// happens here, on use, as well as on the timer, so a token is never
    /// honoured past its fifteen minutes even if the timer is late.
    pub fn current(&self) -> (String, u64) {
        let mut t = self.token.lock().unwrap_or_else(|e| e.into_inner());
        if Instant::now() >= t.expires {
            *t = Token::fresh();
        }
        (t.value.clone(), t.expires_unix)
    }

    /// When the current token runs out.
    pub fn expires_in(&self) -> Duration {
        let t = self.token.lock().unwrap_or_else(|e| e.into_inner());
        t.expires.saturating_duration_since(Instant::now())
    }

    /// Replace the token now, invalidating every URL handed out so far.
    pub fn rotate(&self) {
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = Token::fresh();
    }

    fn accepts(&self, presented: &str) -> bool {
        let (current, _) = self.current();
        constant_time_eq(current.as_bytes(), presented.as_bytes())
    }

    /// The path, relative to the server's `127.0.0.1:<port>`, that fetches the
    /// published item itself.
    pub fn url_path(&self) -> String {
        let (token, _) = self.current();
        format!("/{token}/{}", encode_segment(&self.name))
    }

    /// For a folder, the path that fetches the whole thing as one archive.
    pub fn archive_path(&self) -> Option<String> {
        self.is_dir.then(|| {
            let (token, _) = self.current();
            format!("/{token}/{}.tar.gz", encode_segment(&self.name))
        })
    }
}

/// Where the SSH handler looks for what to serve. Shared between the handler,
/// which lives inside russh, and the session that owns the publication.
pub type Slot = Arc<RwLock<Option<Arc<Shared>>>>;

/// A publication attached to a live session.
pub struct Publication {
    pub shared: Arc<Shared>,
    /// The port the server is listening on, while serving is switched on.
    pub remote_port: Option<u32>,
    /// Replaces the token when it runs out, and tells the UI.
    pub rotator: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Publication {
    fn drop(&mut self) {
        if let Some(t) = self.rotator.take() {
            t.abort();
        }
    }
}

/// What the UI shows about a publication.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub profile_id: String,
    pub path: String,
    pub name: String,
    pub is_dir: bool,
    pub serving: bool,
    /// The URL a program on the server fetches, while serving.
    pub url: Option<String>,
    /// For a folder: the whole folder as a `.tar.gz`.
    pub archive_url: Option<String>,
    /// A command that fetches it, ready to paste on the server.
    pub fetch_command: Option<String>,
    /// Unix seconds at which the current token stops working.
    pub expires_at: u64,
}

impl Publication {
    pub fn status(&self, profile_id: &str) -> Status {
        let (_, expires_at) = self.shared.current();
        let base = self.remote_port.map(|p| format!("http://127.0.0.1:{p}"));
        let url = base
            .as_ref()
            .map(|b| format!("{b}{}", self.shared.url_path()));
        let archive_url = match (&base, self.shared.archive_path()) {
            (Some(b), Some(p)) => Some(format!("{b}{p}")),
            _ => None,
        };
        let fetch_command = match (&url, &archive_url) {
            // A folder is most useful fetched whole and unpacked in one go.
            (_, Some(a)) => Some(format!("curl -fsSL '{a}' | tar xzf -")),
            (Some(u), None) => Some(format!(
                "curl -fsSL -o {} '{u}'",
                crate::transfer::sh_quote(&self.shared.name)
            )),
            _ => None,
        };
        Status {
            profile_id: profile_id.to_string(),
            path: self.shared.path.display().to_string(),
            name: self.shared.name.clone(),
            is_dir: self.shared.is_dir,
            serving: self.remote_port.is_some(),
            url,
            archive_url,
            fetch_command,
            expires_at,
        }
    }
}

// --------------------------------------------------------------------- HTTP

/// Answer one HTTP request on `stream`, then close it.
pub async fn serve<S>(mut stream: S, shared: Arc<Shared>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Err(e) = answer(&mut stream, &shared).await {
        log::debug!("publish: request ended: {e:#}");
    }
    let _ = stream.shutdown().await;
}

async fn answer<S>(stream: &mut S, shared: &Shared) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_head(stream).await?;
    let request_line = head.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();

    let head_only = match method {
        "GET" => false,
        "HEAD" => true,
        _ => {
            return respond_text(
                stream,
                405,
                "Method Not Allowed",
                "only GET and HEAD\n",
                false,
            )
            .await
        }
    };

    // Drop any query string; nothing here uses one.
    let target = target.split('?').next().unwrap_or_default();
    let mut segments = target.trim_start_matches('/').splitn(2, '/');
    let token = segments.next().unwrap_or_default();
    let rest = percent_decode(segments.next().unwrap_or_default());

    // A wrong token and an expired one look the same from outside, and neither
    // reveals whether anything is published here at all.
    if !shared.accepts(token) {
        return respond_text(
            stream,
            404,
            "Not Found",
            "not found — the link may have expired; ask easySSH for the current one\n",
            head_only,
        )
        .await;
    }

    let rest = rest.trim_end_matches('/');
    if !shared.is_dir {
        return if rest.is_empty() || rest == shared.name {
            send_file(stream, &shared.path, &shared.name, head_only).await
        } else {
            respond_text(stream, 404, "Not Found", "not found\n", head_only).await
        };
    }

    let archive_name = format!("{}.tar.gz", shared.name);
    if rest == archive_name {
        return send_archive(stream, &shared.path, &archive_name, head_only).await;
    }
    if rest.is_empty() || rest == shared.name {
        let listing = list_folder(&shared.path, &shared.name, token, &archive_name);
        return respond_text(stream, 200, "OK", &listing, head_only).await;
    }
    let Some(inside) = rest
        .strip_prefix(&shared.name)
        .and_then(|r| r.strip_prefix('/'))
    else {
        return respond_text(stream, 404, "Not Found", "not found\n", head_only).await;
    };
    match resolve_inside(&shared.path, inside) {
        Some(file) if file.is_file() => {
            let name = file
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            send_file(stream, &file, &name, head_only).await
        }
        Some(dir) if dir.is_dir() => {
            let listing = list_folder(&shared.path, &shared.name, token, &archive_name);
            respond_text(stream, 200, "OK", &listing, head_only).await
        }
        _ => respond_text(stream, 404, "Not Found", "not found\n", head_only).await,
    }
}

/// Read up to the blank line that ends the request head.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<String> {
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut byte))
            .await
            .map_err(|_| anyhow!("the client sent no request"))??;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&byte[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.windows(2).any(|w| w == b"\n\n") {
            break;
        }
        if head.len() > MAX_HEAD {
            return Err(anyhow!("request head too large"));
        }
    }
    Ok(String::from_utf8_lossy(&head).to_string())
}

/// Map a path requested inside a published folder to a real path, or `None`
/// if it would leave the folder.
///
/// Two checks, because either alone has a hole: the components are vetted so
/// `..` and absolute paths are refused outright, and the result is
/// canonicalised and compared with the folder, so a symlink inside it cannot
/// point the request somewhere else on the disk.
pub fn resolve_inside(root: &Path, rel: &str) -> Option<PathBuf> {
    let rel = Path::new(rel);
    if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return None;
    }
    let candidate = root.join(rel).canonicalize().ok()?;
    let root = root.canonicalize().ok()?;
    candidate.starts_with(&root).then_some(candidate)
}

/// A plain-text index of a published folder: one fetchable path per line, so
/// an agent can read it and pick what it needs.
fn list_folder(root: &Path, name: &str, token: &str, archive_name: &str) -> String {
    let mut out = format!(
        "# {name} — published by easySSH\n\
         # Whole folder: /{token}/{}\n\
         # Each file below is fetchable at /{token}/{}/<path>\n",
        encode_segment(archive_name),
        encode_segment(name)
    );
    let mut stack = vec![root.to_path_buf()];
    let mut count = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = read.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            // Do not follow links out of the folder while listing, for the same
            // reason `resolve_inside` refuses to serve through them.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
            } else if let Ok(rel) = path.strip_prefix(root) {
                out.push_str(&rel.to_string_lossy().replace('\\', "/"));
                out.push('\n');
                count += 1;
                if count >= MAX_LISTED {
                    out.push_str("# … listing truncated; fetch the archive for everything\n");
                    return out;
                }
            }
        }
    }
    out
}

async fn respond_text<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u16,
    reason: &str,
    body: &str,
    head_only: bool,
) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    if !head_only {
        stream.write_all(body.as_bytes()).await?;
    }
    stream.flush().await?;
    Ok(())
}

async fn send_file<S: AsyncWrite + Unpin>(
    stream: &mut S,
    path: &Path,
    name: &str,
    head_only: bool,
) -> Result<()> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => {
            return respond_text(
                stream,
                404,
                "Not Found",
                "the file is no longer there\n",
                head_only,
            )
            .await
        }
    };
    let len = file.metadata().await?.len();
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {len}\r\n\
         Content-Disposition: attachment; filename=\"{}\"\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        name.replace(['"', '\r', '\n'], "_")
    );
    stream.write_all(head.as_bytes()).await?;
    if !head_only {
        tokio::io::copy(&mut file, stream).await?;
    }
    stream.flush().await?;
    Ok(())
}

async fn send_archive<S: AsyncWrite + Unpin>(
    stream: &mut S,
    folder: &Path,
    name: &str,
    head_only: bool,
) -> Result<()> {
    let tmp = std::env::temp_dir().join(format!(
        "easyssh-publish-{}-{}.tar.gz",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let (src, out) = (folder.to_path_buf(), tmp.clone());
    let packed = tokio::task::spawn_blocking(move || crate::transfer::pack(&src, &out)).await;
    let result = match packed {
        Ok(Ok(_)) => send_file(stream, &tmp, name, head_only).await,
        _ => {
            respond_text(
                stream,
                500,
                "Internal Server Error",
                "could not pack the folder\n",
                head_only,
            )
            .await
        }
    };
    let _ = std::fs::remove_file(&tmp);
    result
}

// ------------------------------------------------------------------ helpers

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Percent-encode one URL path segment.
pub fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Decode `%XX` escapes. Malformed escapes are kept literally rather than
/// guessed at.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("easyssh-publish-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Run one request against `serve` over an in-memory pipe and return the
    /// raw response.
    async fn get(shared: Arc<Shared>, request: &str) -> String {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(serve(server, shared));
        client.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap();
        String::from_utf8_lossy(&out).to_string()
    }

    fn req(path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    }

    #[tokio::test]
    async fn a_published_file_is_served_with_the_current_token() {
        let dir = scratch("file");
        let path = dir.join("report.txt");
        std::fs::write(&path, "the numbers").unwrap();
        let shared = Arc::new(Shared::new(&path).unwrap());

        let resp = get(shared.clone(), &req(&shared.url_path())).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.ends_with("the numbers"), "{resp}");
        assert!(resp.contains("Content-Length: 11"));
    }

    #[tokio::test]
    async fn a_wrong_or_rotated_token_is_refused() {
        let dir = scratch("token");
        let path = dir.join("secret.txt");
        std::fs::write(&path, "shh").unwrap();
        let shared = Arc::new(Shared::new(&path).unwrap());

        let wrong = get(shared.clone(), &req("/0000/secret.txt")).await;
        assert!(wrong.starts_with("HTTP/1.1 404"), "{wrong}");
        assert!(!wrong.contains("shh"));

        // A URL handed out before a rotation stops working after it.
        let old = shared.url_path();
        shared.rotate();
        let stale = get(shared.clone(), &req(&old)).await;
        assert!(stale.starts_with("HTTP/1.1 404"), "{stale}");
        let fresh = get(shared.clone(), &req(&shared.url_path())).await;
        assert!(fresh.starts_with("HTTP/1.1 200"), "{fresh}");
    }

    #[tokio::test]
    async fn a_folder_serves_a_listing_its_files_and_an_archive() {
        let dir = scratch("folder");
        let root = dir.join("data set");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a.csv"), "1,2").unwrap();
        std::fs::write(root.join("sub/b.txt"), "bee").unwrap();
        let shared = Arc::new(Shared::new(&root).unwrap());
        let (token, _) = shared.current();

        let listing = get(shared.clone(), &req(&shared.url_path())).await;
        assert!(
            listing.contains("a.csv") && listing.contains("sub/b.txt"),
            "{listing}"
        );

        let file = get(
            shared.clone(),
            &req(&format!("/{token}/data%20set/sub/b.txt")),
        )
        .await;
        assert!(file.ends_with("bee"), "{file}");

        let archive = get(shared.clone(), &req(&shared.archive_path().unwrap())).await;
        assert!(archive.starts_with("HTTP/1.1 200"), "{}", &archive[..60]);
        assert!(archive.contains("data set.tar.gz"));
    }

    /// The whole point of the token is that only the published item is
    /// reachable. A request must not climb out of the folder.
    #[tokio::test]
    async fn requests_cannot_escape_the_published_folder() {
        let dir = scratch("escape");
        let root = dir.join("shared");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(dir.join("private.txt"), "keep out").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("private.txt"), root.join("link.txt")).unwrap();
        let shared = Arc::new(Shared::new(&root).unwrap());
        let (token, _) = shared.current();

        for path in [
            format!("/{token}/shared/../private.txt"),
            format!("/{token}/shared/%2e%2e/private.txt"),
            format!("/{token}/shared/%2E%2E%2Fprivate.txt"),
            format!("/{token}/shared/link.txt"),
        ] {
            let resp = get(shared.clone(), &req(&path)).await;
            assert!(
                !resp.contains("keep out"),
                "{path} leaked the file:\n{resp}"
            );
        }
    }

    #[tokio::test]
    async fn only_get_and_head_are_answered() {
        let dir = scratch("method");
        let path = dir.join("f.txt");
        std::fs::write(&path, "x").unwrap();
        let shared = Arc::new(Shared::new(&path).unwrap());
        let resp = get(
            shared.clone(),
            &format!("DELETE {} HTTP/1.1\r\n\r\n", shared.url_path()),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 405"), "{resp}");
    }

    /// The whole path, end to end: easySSH asks the server for a remote
    /// forward, and a program on the server fetches the file from its own
    /// loopback address, through the SSH session, from this machine.
    #[tokio::test]
    async fn a_program_on_the_server_fetches_the_file_over_the_session() {
        let dir = scratch("e2e");
        let path = dir.join("model.bin");
        std::fs::write(&path, "weights").unwrap();

        let port = crate::testserver::start().await;
        let kh = dir.join("known_hosts");
        let session = crate::ssh::connect_password(
            "127.0.0.1",
            port,
            "someone",
            crate::testserver::PASSWORD,
            &kh,
        )
        .await
        .expect("connect");

        let shared = Arc::new(Shared::new(&path).unwrap());
        *session.publish.write().unwrap() = Some(shared.clone());
        let remote_port = session
            .handle
            .tcpip_forward("127.0.0.1", 0)
            .await
            .expect("remote forward");
        assert_ne!(remote_port, 0);

        // Stand in for curl on the server.
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", remote_port as u16))
            .await
            .expect("connect to the forwarded port");
        client
            .write_all(req(&shared.url_path()).as_bytes())
            .await
            .unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        let resp = String::from_utf8_lossy(&out);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.ends_with("weights"), "{resp}");

        // Unpublished: the same URL now finds nothing to answer it.
        *session.publish.write().unwrap() = None;
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", remote_port as u16))
            .await
            .unwrap();
        let _ = client.write_all(req(&shared.url_path()).as_bytes()).await;
        let mut out = Vec::new();
        let _ = client.read_to_end(&mut out).await;
        assert!(
            !String::from_utf8_lossy(&out).contains("weights"),
            "served after being unpublished"
        );
    }

    #[test]
    fn tokens_are_long_random_and_last_fifteen_minutes() {
        let dir = scratch("lifetime");
        let path = dir.join("f.txt");
        std::fs::write(&path, "x").unwrap();
        let a = Shared::new(&path).unwrap();
        let b = Shared::new(&path).unwrap();
        let (ta, _) = a.current();
        assert_eq!(ta.len(), 32, "128 bits, hex");
        assert_ne!(ta, b.current().0);
        let left = a.expires_in();
        assert!(left <= TOKEN_LIFETIME && left > TOKEN_LIFETIME - Duration::from_secs(5));
    }

    #[test]
    fn url_segments_round_trip() {
        let name = "my file (1)+é.txt";
        assert_eq!(percent_decode(&encode_segment(name)), name);
        assert_eq!(percent_decode("bad%zzescape"), "bad%zzescape");
        assert_eq!(percent_decode("trailing%4"), "trailing%4");
    }
}
