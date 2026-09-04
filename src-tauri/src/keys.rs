//! Discovery, generation and inspection of local SSH private keys.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use rand::rng;
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};

use crate::model::KeyInfo;

/// The key easySSH generates for you when you do not already have one.
pub const DEFAULT_KEY_NAME: &str = "id_easyssh_ed25519";

/// Files in `~/.ssh` that are never private keys.
const NON_KEY_FILES: &[&str] = &[
    "known_hosts",
    "known_hosts.old",
    "authorized_keys",
    "config",
    "environment",
    "rc",
];

/// Where the conventional per-user `.ssh` directory is. Creates nothing —
/// computing a path should not have side effects.
pub fn default_ssh_dir_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".ssh"))
}

/// Make sure a `.ssh` directory exists and is private.
pub fn ensure_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    harden_dir(dir)?;
    Ok(())
}

/// `~/.ssh` must be 0700 or OpenSSH refuses to use the keys inside it.
fn harden_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Private key files must be readable only by their owner, or OpenSSH refuses
/// to load them.
#[cfg(unix)]
fn harden_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Windows has no POSIX mode bits; the equivalent is to strip the inherited
/// ACEs and grant the current account alone. Best-effort — a key that could not
/// be locked down is still a usable key for easySSH itself, and only the
/// external `ssh` client is strict about it.
#[cfg(windows)]
fn harden_file(path: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let Ok(user) = std::env::var("USERNAME") else {
        return Ok(());
    };
    if user.is_empty() {
        return Ok(());
    }

    let run = |args: &[String]| {
        let _ = Command::new("icacls")
            .arg(path)
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    };
    run(&["/inheritance:r".to_string()]);
    run(&["/grant:r".to_string(), format!("{user}:F")]);
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn harden_file(_path: &Path) -> Result<()> {
    Ok(())
}

/// Read a public key, either from a `.pub` file or from the private key beside it.
pub fn public_key_for(private_path: &Path) -> Result<PublicKey> {
    let pub_path = pub_path_for(private_path);
    if pub_path.exists() {
        let text = fs::read_to_string(&pub_path)
            .with_context(|| format!("reading {}", pub_path.display()))?;
        return PublicKey::from_openssh(text.trim())
            .with_context(|| format!("parsing {}", pub_path.display()));
    }
    // No `.pub` beside it: derive one, which only works for an unencrypted key.
    let key = PrivateKey::read_openssh_file(private_path)
        .with_context(|| format!("reading {}", private_path.display()))?;
    if key.is_encrypted() {
        return Err(anyhow!(
            "{} has no matching .pub file and the private key is passphrase-protected",
            private_path.display()
        ));
    }
    Ok(key.public_key().clone())
}

pub fn pub_path_for(private_path: &Path) -> PathBuf {
    let mut s = private_path.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}

/// The single line that goes into the remote's `authorized_keys`.
pub fn authorized_keys_line(private_path: &Path) -> Result<String> {
    Ok(public_key_for(private_path)?
        .to_openssh()?
        .trim()
        .to_string())
}

/// Every usable private key in `dir`, easySSH's own key first.
pub fn list_keys_in(dir: &Path) -> Result<Vec<KeyInfo>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || name.ends_with(".pub") || NON_KEY_FILES.contains(&name.as_str())
        {
            continue;
        }
        if let Some(info) = inspect(&path) {
            out.push(info);
        }
    }
    // Our own generated key first, then alphabetical: stable and predictable in the picker.
    out.sort_by(|a, b| {
        let rank = |n: &str| if n == DEFAULT_KEY_NAME { 0 } else { 1 };
        rank(&a.name)
            .cmp(&rank(&b.name))
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(out)
}

/// Describe a key file, or return `None` if it is not an OpenSSH private key.
pub fn inspect(path: &Path) -> Option<KeyInfo> {
    let text = fs::read_to_string(path).ok()?;
    if !text.contains("PRIVATE KEY") {
        return None;
    }
    let key = PrivateKey::from_openssh(&text).ok()?;
    // For an encrypted key the embedded public half is still readable in the clear.
    let public = key.public_key();
    Some(KeyInfo {
        path: path.display().to_string(),
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        algorithm: friendly_algorithm(public.algorithm()),
        fingerprint: public.fingerprint(Default::default()).to_string(),
        comment: public.comment().to_string(),
        encrypted: key.is_encrypted(),
    })
}

/// Inspect a key at an arbitrary path the user picked from a file dialog.
pub fn inspect_path(path: &str) -> Result<KeyInfo> {
    let p = PathBuf::from(path);
    if !p.exists() {
        return Err(anyhow!("{} does not exist", p.display()));
    }
    // Tolerate the user picking `id_ed25519.pub` when they meant `id_ed25519`.
    let p = if p.extension().and_then(|e| e.to_str()) == Some("pub") {
        p.with_extension("")
    } else {
        p
    };
    inspect(&p).ok_or_else(|| anyhow!("{} is not an OpenSSH private key", p.display()))
}

fn friendly_algorithm(alg: Algorithm) -> String {
    match alg {
        Algorithm::Ed25519 => "Ed25519".into(),
        Algorithm::Rsa { .. } => "RSA".into(),
        Algorithm::Ecdsa { curve } => format!("ECDSA {}", curve.as_str()),
        Algorithm::Dsa => "DSA".into(),
        ref other => other.as_str().to_string(),
    }
}

/// Which algorithm the UI asked us to generate.
pub fn algorithm_from_str(s: &str) -> Result<Algorithm> {
    match s.to_ascii_lowercase().as_str() {
        "ed25519" => Ok(Algorithm::Ed25519),
        "rsa" => Ok(Algorithm::Rsa { hash: None }),
        other => Err(anyhow!("unsupported key algorithm: {other}")),
    }
}

/// Generate a new key pair in `dir` and return its description.
///
/// `name` is the private key's file name inside `dir`; the public half is
/// written to `<name>.pub`.
/// Refuses to overwrite an existing file.
pub fn generate(
    dir: &Path,
    name: &str,
    algorithm: &str,
    comment: &str,
    passphrase: Option<&str>,
) -> Result<KeyInfo> {
    let name = name.trim();
    if name.is_empty() {
        return Err(anyhow!("the key needs a file name"));
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(anyhow!("the key name must be a plain file name"));
    }
    ensure_dir(dir)?;
    let path = dir.join(name);
    if path.exists() {
        return Err(anyhow!("{} already exists", path.display()));
    }

    let algorithm = algorithm_from_str(algorithm)?;
    let mut rng = rng();
    let mut key = PrivateKey::random(&mut rng, algorithm)
        .map_err(|e| anyhow!("could not generate the key: {e}"))?;
    key.set_comment(comment);

    let key = match passphrase {
        Some(p) if !p.is_empty() => key
            .encrypt(&mut rng, p)
            .map_err(|e| anyhow!("could not encrypt the key: {e}"))?,
        _ => key,
    };

    key.write_openssh_file(&path, LineEnding::LF)
        .with_context(|| format!("writing {}", path.display()))?;
    harden_file(&path)?;

    let pub_path = pub_path_for(&path);
    let mut pub_line = key.public_key().to_openssh()?;
    pub_line.push('\n');
    fs::write(&pub_path, pub_line).with_context(|| format!("writing {}", pub_path.display()))?;

    inspect(&path).ok_or_else(|| anyhow!("generated key at {} is unreadable", path.display()))
}

/// The key we should offer by default in `dir`: an existing easySSH key, or a
/// freshly generated one.
pub fn ensure_default_key(dir: &Path) -> Result<KeyInfo> {
    ensure_dir(dir)?;
    let path = dir.join(DEFAULT_KEY_NAME);
    if path.exists() {
        if let Some(info) = inspect(&path) {
            return Ok(info);
        }
    }
    let comment = format!("easySSH@{}", hostname());
    generate(dir, DEFAULT_KEY_NAME, "ed25519", &comment, None)
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "local".into())
}
