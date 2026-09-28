//! Sending files and folders to a server, and fetching them back.
//!
//! Everything travels as one gzip-compressed tar stream over a single SSH
//! channel: `tar` on this side, `tar` on the other. That makes a folder of ten
//! thousand small files one transfer instead of ten thousand round trips, keeps
//! permissions and timestamps, and needs nothing on the server beyond the `tar`
//! every Unix-like system already has.
//!
//! The archive is built in a temporary file rather than streamed straight into
//! the channel. That costs a little disk space for the length of the transfer,
//! and buys an honest progress bar: the total is known before the first byte is
//! sent.

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use russh::client::Handle;
use russh::ChannelMsg;
use serde::Serialize;
use tokio::io::AsyncReadExt;

use crate::ssh::Client;

/// How much is read and sent at a time. Large enough to keep an SSH channel's
/// window full, small enough that progress moves smoothly.
const CHUNK: usize = 256 * 1024;

/// Where a transfer has got to, for the progress bar.
#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    /// `packing`, `sending`, `receiving` or `unpacking`.
    pub phase: &'static str,
    pub done: u64,
    /// `None` when the size is not known in advance — a download, whose
    /// compressed size only the server finds out as it goes.
    pub total: Option<u64>,
}

/// What a finished transfer did, for the confirmation the UI shows.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    /// Where it ended up: a remote directory for a send, a local one for a
    /// receive.
    pub destination: String,
    /// The top-level names that arrived there.
    pub names: Vec<String>,
    /// Compressed bytes that crossed the wire.
    pub bytes: u64,
}

/// One entry in a remote directory listing.
#[derive(Debug, Clone, Serialize)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
}

/// A remote directory, with its absolute path resolved on the server.
#[derive(Debug, Clone, Serialize)]
pub struct RemoteListing {
    pub path: String,
    pub entries: Vec<RemoteEntry>,
}

// ----------------------------------------------------------------- quoting

/// Quote a string for a POSIX shell, so it arrives as exactly one argument
/// whatever it contains.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A remote path as a shell word, with a leading `~` still meaning home.
///
/// Quoting alone would turn `~/uploads` into a directory literally named `~`,
/// which is not what anyone typing it means. Anything after the tilde is still
/// quoted, so a path cannot smuggle in a command.
pub fn remote_path(p: &str) -> String {
    let p = p.trim();
    if p.is_empty() || p == "~" {
        "\"$HOME\"".into()
    } else if let Some(rest) = p.strip_prefix("~/") {
        format!("\"$HOME\"/{}", sh_quote(rest))
    } else {
        sh_quote(p)
    }
}

// ------------------------------------------------------------ local archives

/// The name a path is known by at the far end: its last component.
fn leaf_name(path: &Path) -> Result<String> {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| anyhow!("{} has no name to send it under", path.display()))
}

/// Pack a file or a folder into a `.tar.gz` at `out`, under its own name, so
/// it unpacks as that one entry. Returns the archive's size.
pub fn pack(src: &Path, out: &Path) -> Result<u64> {
    let name = leaf_name(src)?;
    let meta = std::fs::metadata(src).with_context(|| format!("cannot read {}", src.display()))?;

    let file = File::create(out).with_context(|| format!("cannot write {}", out.display()))?;
    let gz = flate2::write::GzEncoder::new(BufWriter::new(file), flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    // A symlink inside the folder is sent as a link, not as whatever it points
    // at: following it could pull in a whole other tree, or loop.
    tar.follow_symlinks(false);

    if meta.is_dir() {
        tar.append_dir_all(&name, src)
    } else {
        tar.append_path_with_name(src, &name)
    }
    .with_context(|| format!("could not pack {}", src.display()))?;

    let gz = tar.into_inner().context("could not finish the archive")?;
    let mut writer = gz.finish().context("could not finish compressing")?;
    std::io::Write::flush(&mut writer)?;
    drop(writer);
    Ok(std::fs::metadata(out)?.len())
}

/// Unpack a `.tar.gz` into `dest`, returning the top-level names it held.
///
/// Relies on `tar`'s own guard against entries that would land outside
/// `dest` — `../` components and absolute paths are refused, which matters
/// here because the archive came from a machine this one does not control.
pub fn unpack(archive: &Path, dest: &Path) -> Result<Vec<String>> {
    std::fs::create_dir_all(dest).with_context(|| format!("cannot create {}", dest.display()))?;

    let names = top_level_names(archive)?;
    let file = File::open(archive)?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(BufReader::new(file)));
    tar.set_preserve_permissions(true);
    tar.set_overwrite(true);
    tar.unpack(dest)
        .with_context(|| format!("could not unpack into {}", dest.display()))?;
    Ok(names)
}

/// The distinct first path components in an archive, in order of appearance.
fn top_level_names(archive: &Path) -> Result<Vec<String>> {
    let file = File::open(archive)?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(BufReader::new(file)));
    let mut names: Vec<String> = Vec::new();
    for entry in tar
        .entries()
        .context("the archive is not a valid .tar.gz")?
    {
        let entry = entry?;
        let path = entry.path()?.into_owned();
        if let Some(Component::Normal(first)) = path.components().next() {
            let first = first.to_string_lossy().to_string();
            if !names.contains(&first) {
                names.push(first);
            }
        }
    }
    Ok(names)
}

/// A temporary file that removes itself, so an abandoned transfer does not
/// leave a copy of someone's folder lying in the temp directory.
struct TempArchive(PathBuf);

impl TempArchive {
    fn new(tag: &str) -> Self {
        let name = format!(
            "easyssh-{tag}-{}-{}.tar.gz",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );
        Self(std::env::temp_dir().join(name))
    }
}

impl Drop for TempArchive {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ------------------------------------------------------------------ remote

/// What the remote side of an exec said, gathered after the fact.
struct Finished {
    code: Option<u32>,
    stderr: String,
}

/// Drain a channel until it closes, collecting stderr and the exit status.
async fn finish(channel: &mut russh::Channel<russh::client::Msg>) -> Finished {
    let mut stderr = Vec::new();
    let mut code = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::ExtendedData { ref data, ext: 1 } => stderr.extend_from_slice(data),
            ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
            _ => {}
        }
    }
    Finished {
        code,
        stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
    }
}

/// Turn a failed remote `tar` into a sentence worth reading.
fn remote_failure(what: &str, done: &Finished) -> anyhow::Error {
    let detail = if done.stderr.is_empty() {
        match done.code {
            Some(c) => format!("the server's tar exited with status {c}"),
            None => "the connection closed before the server finished".into(),
        }
    } else {
        done.stderr.clone()
    };
    if detail.contains("tar: not found") || detail.contains("command not found") {
        return anyhow!("{what}: the server has no `tar` command to unpack with");
    }
    anyhow!("{what}: {detail}")
}

/// Send a local file or folder into `remote_dir` on the server, creating the
/// directory if it does not exist. Anything already there under the same name
/// is overwritten.
pub async fn send(
    handle: &Handle<Client>,
    local: &Path,
    remote_dir: &str,
    progress: impl Fn(Progress),
) -> Result<Outcome> {
    if !local.exists() {
        bail!("{} does not exist", local.display());
    }
    let name = leaf_name(local)?;

    progress(Progress {
        phase: "packing",
        done: 0,
        total: None,
    });
    let archive = TempArchive::new("send");
    let (src, out) = (local.to_path_buf(), archive.0.clone());
    let size = tokio::task::spawn_blocking(move || pack(&src, &out))
        .await
        .map_err(|e| anyhow!("packing was interrupted: {e}"))??;

    let dir = remote_path(remote_dir);
    // `set -e` so a directory that cannot be created stops the script before
    // tar starts reading a stream it has nowhere to put. The final `pwd`
    // reports where `~` and relative paths actually led.
    let script = format!("set -e; d={dir}; mkdir -p -- \"$d\"; cd -- \"$d\"; tar xzf -; pwd >&2");

    let mut channel = handle
        .channel_open_session()
        .await
        .context("could not open a channel for the transfer")?;
    channel.exec(true, script).await?;

    let mut file = tokio::fs::File::open(&archive.0).await?;
    let mut buf = vec![0u8; CHUNK];
    let mut sent = 0u64;
    let mut stream_err = None;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        if let Err(e) = channel.data(&buf[..n]).await {
            // The server stopped reading — usually because the script failed.
            // Its own message says why, so collect that rather than report a
            // bare "channel closed".
            stream_err = Some(e);
            break;
        }
        sent += n as u64;
        progress(Progress {
            phase: "sending",
            done: sent,
            total: Some(size),
        });
    }
    let _ = channel.eof().await;
    let done = finish(&mut channel).await;

    if done.code != Some(0) || stream_err.is_some() {
        return Err(remote_failure(&format!("could not send {name}"), &done));
    }
    // With `pwd >&2` as the last command, the resolved directory is the last
    // line of stderr; anything before it is tar grumbling about timestamps.
    let destination = done
        .stderr
        .lines()
        .last()
        .map(str::to_string)
        .unwrap_or_else(|| remote_dir.to_string());

    Ok(Outcome {
        destination,
        names: vec![name],
        bytes: sent,
    })
}

/// Fetch a remote file or folder into `local_dir` on this machine. Anything
/// already there under the same name is overwritten.
pub async fn receive(
    handle: &Handle<Client>,
    remote: &str,
    local_dir: &Path,
    progress: impl Fn(Progress),
) -> Result<Outcome> {
    let target = remote_path(remote);
    // Pack from the parent directory so the archive holds just the one name,
    // not the whole path leading to it. `COPYFILE_DISABLE` stops macOS's tar
    // adding `._name` AppleDouble files for extended attributes, which would
    // otherwise arrive here as clutter beside every file; GNU tar ignores it.
    let script = format!(
        "p={target}; [ -e \"$p\" ] || {{ echo \"no such file or folder: $p\" >&2; exit 2; }}; \
         cd -- \"$(dirname -- \"$p\")\" && COPYFILE_DISABLE=1 tar czf - -- \"$(basename -- \"$p\")\""
    );

    let mut channel = handle
        .channel_open_session()
        .await
        .context("could not open a channel for the transfer")?;
    channel.exec(true, script).await?;
    // The script reads nothing; close its stdin so nothing waits on it.
    let _ = channel.eof().await;

    let archive = TempArchive::new("receive");
    let mut out = tokio::fs::File::create(&archive.0).await?;
    let mut got = 0u64;
    let mut stderr = Vec::new();
    let mut code = None;

    progress(Progress {
        phase: "receiving",
        done: 0,
        total: None,
    });
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => {
                tokio::io::AsyncWriteExt::write_all(&mut out, data).await?;
                got += data.len() as u64;
                progress(Progress {
                    phase: "receiving",
                    done: got,
                    total: None,
                });
            }
            ChannelMsg::ExtendedData { ref data, ext: 1 } => stderr.extend_from_slice(data),
            ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
            _ => {}
        }
    }
    tokio::io::AsyncWriteExt::flush(&mut out).await?;
    drop(out);

    if code != Some(0) {
        let done = Finished {
            code,
            stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
        };
        return Err(remote_failure(&format!("could not fetch {remote}"), &done));
    }

    progress(Progress {
        phase: "unpacking",
        done: got,
        total: Some(got),
    });
    let (src, dest) = (archive.0.clone(), local_dir.to_path_buf());
    let names = tokio::task::spawn_blocking(move || unpack(&src, &dest))
        .await
        .map_err(|e| anyhow!("unpacking was interrupted: {e}"))??;

    Ok(Outcome {
        destination: local_dir.display().to_string(),
        names,
        bytes: got,
    })
}

/// List a remote directory, for choosing what to fetch or where to send.
///
/// The first line the script prints is the directory's absolute path, so `~`
/// and relative paths come back resolved and the UI can walk up from them.
pub async fn list_remote(handle: &Handle<Client>, dir: &str) -> Result<RemoteListing> {
    let d = remote_path(dir);
    let script = format!(
        "cd -- {d} 2>/dev/null || {{ echo \"cannot open {}\" >&2; exit 3; }}; pwd; \
         for f in .* *; do \
           case \"$f\" in .|..) continue;; esac; \
           [ -e \"$f\" ] || [ -L \"$f\" ] || continue; \
           if [ -d \"$f\" ]; then printf 'd\\t%s\\n' \"$f\"; else printf 'f\\t%s\\n' \"$f\"; fi; \
         done",
        dir.replace(['"', '`', '$', '\\'], "")
    );
    let out = crate::ssh::exec(handle, &script).await?;
    if out.code != 0 {
        let msg = out.stderr.trim();
        bail!(if msg.is_empty() {
            format!("could not list {dir}")
        } else {
            msg.to_string()
        });
    }

    let mut lines = out.stdout.lines();
    let path = lines.next().unwrap_or(dir).to_string();
    let mut entries: Vec<RemoteEntry> = lines
        .filter_map(|l| {
            let (kind, name) = l.split_once('\t')?;
            Some(RemoteEntry {
                name: name.to_string(),
                is_dir: kind == "d",
            })
        })
        .collect();
    // Folders first, then files, each alphabetical ignoring case.
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(RemoteListing { path, entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("easyssh-transfer-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn quoting_survives_anything_a_filename_can_hold() {
        assert_eq!(sh_quote("plain"), "'plain'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
        // Command substitution stays inert inside single quotes.
        assert_eq!(sh_quote("$(rm -rf ~)"), "'$(rm -rf ~)'");
    }

    #[test]
    fn a_leading_tilde_still_means_home() {
        assert_eq!(remote_path("~"), "\"$HOME\"");
        assert_eq!(remote_path(""), "\"$HOME\"");
        assert_eq!(remote_path("~/up loads"), "\"$HOME\"/'up loads'");
        assert_eq!(remote_path("/srv/data"), "'/srv/data'");
        // A tilde anywhere else is just a character.
        assert_eq!(remote_path("/tmp/~x"), "'/tmp/~x'");
    }

    /// A real shell, not a string comparison: the quoted forms must expand to
    /// exactly the paths intended.
    #[cfg(unix)]
    #[test]
    fn quoted_remote_paths_expand_correctly_under_sh() {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "printf '%s\\n' {} {}",
                remote_path("~/a b"),
                remote_path("x'y$(echo no)")
            ))
            .env("HOME", "/home/test")
            .output()
            .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        assert_eq!(text, "/home/test/a b\nx'y$(echo no)\n");
    }

    /// Connect to a test server that runs commands under a real shell, with
    /// `HOME` in a scratch directory standing in for the remote machine.
    #[cfg(unix)]
    async fn remote(tag: &str) -> (russh::client::Handle<Client>, PathBuf, PathBuf) {
        let root = scratch(tag);
        let home = root.join("remote-home");
        std::fs::create_dir_all(&home).unwrap();
        let port = crate::testserver::start_with_shell(home.clone()).await;
        let kh = root.join("known_hosts");
        let session = crate::ssh::connect_password(
            "127.0.0.1",
            port,
            "someone",
            crate::testserver::PASSWORD,
            &kh,
        )
        .await
        .expect("connect");
        let handle = std::sync::Arc::try_unwrap(session.handle)
            .unwrap_or_else(|_| panic!("the handle is shared"));
        (handle, root, home)
    }

    /// A folder sent with `~/…` lands in the remote home, whole, and the
    /// directory is created on the way.
    #[cfg(unix)]
    #[tokio::test]
    async fn sends_a_folder_into_a_new_remote_directory() {
        let (handle, root, home) = remote("send").await;
        let src = root.join("site");
        std::fs::create_dir_all(src.join("css")).unwrap();
        std::fs::write(src.join("index.html"), "<h1>hi</h1>").unwrap();
        std::fs::write(src.join("css/main.css"), "body{}").unwrap();

        let seen = std::sync::Mutex::new(Vec::new());
        let out = send(&handle, &src, "~/deploy/new", |p| {
            seen.lock().unwrap().push(p.phase)
        })
        .await
        .expect("send");

        assert_eq!(out.names, vec!["site".to_string()]);
        assert_eq!(
            std::fs::read_to_string(home.join("deploy/new/site/index.html")).unwrap(),
            "<h1>hi</h1>"
        );
        assert!(home.join("deploy/new/site/css/main.css").is_file());
        assert!(
            out.destination.ends_with("deploy/new"),
            "not the resolved remote path: {}",
            out.destination
        );
        let seen = seen.lock().unwrap();
        assert!(
            seen.contains(&"packing") && seen.contains(&"sending"),
            "{seen:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn receives_a_remote_folder_into_a_local_directory() {
        let (handle, root, home) = remote("receive").await;
        std::fs::create_dir_all(home.join("logs/2026")).unwrap();
        std::fs::write(home.join("logs/2026/app.log"), "started").unwrap();

        let dest = root.join("downloads");
        let out = receive(&handle, "~/logs", &dest, |_| {})
            .await
            .expect("receive");

        assert_eq!(out.names, vec!["logs".to_string()]);
        assert_eq!(
            std::fs::read_to_string(dest.join("logs/2026/app.log")).unwrap(),
            "started"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fetching_something_that_is_not_there_says_so() {
        let (handle, root, _) = remote("missing").await;
        let err = receive(&handle, "~/nope", &root.join("d"), |_| {})
            .await
            .expect_err("a missing path must fail");
        assert!(err.to_string().contains("no such file or folder"), "{err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lists_a_remote_directory_folders_first() {
        let (handle, _, home) = remote("list").await;
        std::fs::create_dir_all(home.join("zeta")).unwrap();
        std::fs::write(home.join("alpha.txt"), "").unwrap();
        std::fs::write(home.join(".hidden"), "").unwrap();

        let listing = list_remote(&handle, "~").await.expect("list");
        assert_eq!(
            std::fs::canonicalize(&listing.path).unwrap(),
            std::fs::canonicalize(&home).unwrap()
        );
        let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names[0], "zeta", "folders should come first: {names:?}");
        assert!(names.contains(&"alpha.txt") && names.contains(&".hidden"));
    }

    #[test]
    fn a_folder_round_trips_through_an_archive() {
        let root = scratch("roundtrip");
        let src = root.join("project");
        std::fs::create_dir_all(src.join("nested/deeper")).unwrap();
        std::fs::write(src.join("readme.txt"), "hello").unwrap();
        std::fs::write(src.join("nested/deeper/data.bin"), [0u8, 1, 2, 255]).unwrap();

        let archive = root.join("out.tar.gz");
        assert!(pack(&src, &archive).unwrap() > 0);

        let dest = root.join("unpacked");
        let names = unpack(&archive, &dest).unwrap();
        assert_eq!(names, vec!["project".to_string()]);
        assert_eq!(
            std::fs::read_to_string(dest.join("project/readme.txt")).unwrap(),
            "hello"
        );
        assert_eq!(
            std::fs::read(dest.join("project/nested/deeper/data.bin")).unwrap(),
            vec![0u8, 1, 2, 255]
        );
    }

    #[test]
    fn a_single_file_arrives_under_its_own_name() {
        let root = scratch("single");
        let src = root.join("notes.md");
        std::fs::write(&src, "# hi").unwrap();
        let archive = root.join("out.tar.gz");
        pack(&src, &archive).unwrap();

        let names = unpack(&archive, &root.join("dest")).unwrap();
        assert_eq!(names, vec!["notes.md".to_string()]);
        assert_eq!(
            std::fs::read_to_string(root.join("dest/notes.md")).unwrap(),
            "# hi"
        );
    }

    /// An archive from a hostile server must not write outside the folder the
    /// user chose.
    #[test]
    fn an_archive_cannot_escape_the_destination() {
        let root = scratch("escape");
        let archive = root.join("evil.tar.gz");
        {
            let gz = flate2::write::GzEncoder::new(
                File::create(&archive).unwrap(),
                flate2::Compression::default(),
            );
            let mut tar = tar::Builder::new(gz);
            let mut header = tar::Header::new_gnu();
            let body = b"pwned";
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            // Written raw, because the builder itself refuses `..`.
            let name = b"../escaped.txt";
            header.as_old_mut().name[..name.len()].copy_from_slice(name);
            header.set_cksum();
            tar.append(&header, &body[..]).unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }

        let dest = root.join("dest");
        let _ = unpack(&archive, &dest);
        assert!(
            !root.join("escaped.txt").exists(),
            "an entry was written outside the destination"
        );
    }
}
