//! Discovery, generation and inspection of local SSH private keys.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use rand::rng;
use russh::keys::decode_secret_key;
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

/// How a private key file is encoded, as shown in the key picker.
///
/// `ssh-keygen` writes the OpenSSH format; AWS hands you a `.pem`, which is
/// PKCS#1 or PKCS#8, and PuTTY writes `.ppk`. All three are private keys and
/// all three work here, so all three belong in the list.
pub fn detect_format(text: &str) -> Option<&'static str> {
    if text.trim_start().starts_with("PuTTY-User-Key-File-") {
        return Some("PuTTY");
    }
    for line in text.lines() {
        match line.trim() {
            "-----BEGIN OPENSSH PRIVATE KEY-----" => return Some("OpenSSH"),
            "-----BEGIN RSA PRIVATE KEY-----"
            | "-----BEGIN DSA PRIVATE KEY-----"
            | "-----BEGIN EC PRIVATE KEY-----"
            | "-----BEGIN PRIVATE KEY-----"
            | "-----BEGIN ENCRYPTED PRIVATE KEY-----" => return Some("PEM"),
            _ => {}
        }
    }
    None
}

/// True when the file cannot be read without a passphrase. An encrypted
/// OpenSSH key still exposes its public half, so this only concerns PEM: there
/// the whole structure is ciphertext and even the algorithm is a guess.
fn pem_is_encrypted(text: &str) -> bool {
    text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || text.contains("Proc-Type: 4,ENCRYPTED")
}

/// The algorithm named in a PEM header, for a key we cannot decrypt.
fn pem_algorithm_hint(text: &str) -> String {
    if text.contains("-----BEGIN RSA PRIVATE KEY-----") {
        "RSA".into()
    } else if text.contains("-----BEGIN EC PRIVATE KEY-----") {
        "ECDSA".into()
    } else if text.contains("-----BEGIN DSA PRIVATE KEY-----") {
        "DSA".into()
    } else {
        "encrypted".into()
    }
}

/// Parse a private key in any format easySSH accepts.
///
/// OpenSSH keys go through `ssh-key` directly, because an encrypted one still
/// yields its public half — which is what the picker and `authorized_keys`
/// need. Everything else goes through russh's decoder, the same one that will
/// load the key at connect time, so a key that lists here is a key that works.
pub fn load_private(text: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    if text.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
        if let Ok(key) = PrivateKey::from_openssh(text) {
            return Ok(key);
        }
    }
    decode_secret_key(text, passphrase.filter(|p| !p.is_empty()))
        .map_err(|e| anyhow!("could not read the private key: {e}"))
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
    // No `.pub` beside it — the usual case for a `.pem` from AWS. Derive one,
    // which only works while the private key is not passphrase-protected.
    let text = fs::read_to_string(private_path)
        .with_context(|| format!("reading {}", private_path.display()))?;
    if pem_is_encrypted(&text) {
        return Err(anyhow!(
            "{} has no matching .pub file and the private key is passphrase-protected",
            private_path.display()
        ));
    }
    let key =
        load_private(&text, None).with_context(|| format!("reading {}", private_path.display()))?;
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
    let format = detect_format(&text)?;
    let name = || {
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    };

    match load_private(&text, None) {
        Ok(key) => {
            // For an encrypted OpenSSH key the embedded public half is still
            // readable in the clear.
            let public = key.public_key();
            Some(KeyInfo {
                path: path.display().to_string(),
                name: name(),
                algorithm: friendly_algorithm(public.algorithm()),
                fingerprint: public.fingerprint(Default::default()).to_string(),
                comment: public.comment().to_string(),
                encrypted: key.is_encrypted(),
                format: format.to_string(),
            })
        }
        // A passphrase-protected PEM is a perfectly good key; we simply cannot
        // describe it until the user types the passphrase at connect time.
        // Listing it beats hiding it and leaving them wondering where it went.
        Err(_) if pem_is_encrypted(&text) => Some(KeyInfo {
            path: path.display().to_string(),
            name: name(),
            algorithm: pem_algorithm_hint(&text),
            fingerprint: String::new(),
            comment: String::new(),
            encrypted: true,
            format: format.to_string(),
        }),
        Err(_) => None,
    }
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
    inspect(&p).ok_or_else(|| {
        anyhow!(
            "{} is not a private key easySSH can read. OpenSSH keys, PEM files \
             (including the .pem AWS gives you) and PuTTY .ppk files all work.",
            p.display()
        )
    })
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

/// Copy a private key into `dir`, lock its permissions down, and write the
/// public half beside it.
///
/// This is how a `.pem` downloaded from the AWS console becomes usable: it
/// arrives in `~/Downloads` world-readable, which the system `ssh` refuses to
/// touch — and easySSH hands the terminal over to that `ssh`. Copying it into
/// the `.ssh` directory at 0600, with a `.pub` beside it, makes it behave like
/// any other key here.
pub fn import(dir: &Path, source: &Path) -> Result<KeyInfo> {
    let text =
        fs::read_to_string(source).with_context(|| format!("reading {}", source.display()))?;
    if detect_format(&text).is_none() {
        return Err(anyhow!(
            "{} is not a private key. Choose the .pem file itself, not the .pub or a certificate.",
            source.display()
        ));
    }

    let file_name = source
        .file_name()
        .ok_or_else(|| anyhow!("{} is not a file", source.display()))?;
    ensure_dir(dir)?;
    let dest = dir.join(file_name);

    // Importing a key that is already here is how the user fixes its
    // permissions, so it is a no-op rather than an error — but a *different*
    // key of the same name must never be silently overwritten.
    if dest.exists() && dest != source {
        let existing = fs::read_to_string(&dest).unwrap_or_default();
        if existing.trim() != text.trim() {
            return Err(anyhow!(
                "a different key called {} is already in {}. Rename the file and import it again.",
                file_name.to_string_lossy(),
                dir.display()
            ));
        }
    }
    if dest != source {
        fs::write(&dest, &text).with_context(|| format!("writing {}", dest.display()))?;
    }
    harden_file(&dest)?;

    // A `.pem` has no `.pub`; derive one so the key can be installed on other
    // servers and shown in the public key viewer. An encrypted key cannot be
    // read without its passphrase, and that is not a reason to fail the import.
    let pub_path = pub_path_for(&dest);
    if !pub_path.exists() {
        if let Ok(key) = load_private(&text, None) {
            if !key.is_encrypted() {
                if let Ok(mut line) = key.public_key().to_openssh() {
                    line.push('\n');
                    let _ = fs::write(&pub_path, line);
                }
            }
        }
    }

    inspect(&dest).ok_or_else(|| anyhow!("{} could not be read back", dest.display()))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A 2048-bit RSA key in PKCS#1 PEM — byte for byte the shape of the file
    /// the AWS console hands you when you create a key pair. Test material
    /// only; it protects nothing.
    const PEM_RSA: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwBGetHjW+3bDQpVktdemnk7JXgu1NBWUM+ysifYLDBvJ9ttX
GNZSyQKA4v/dNr0FhAJ8I9BuOTjYCy1YfKylhl5D/DiSSXFPsQzERMmGgAlYvU2U
+FTxpBC11EZg69CPVMKKevfoUD+PZA5zB7Hc1dXFfwqFc5249SdbAwD39VTbrOUI
WECvWZs6/ucQxHHXP2O9qxWqhzb/ddOnqsDHUNoeceiNiCf2anNymovrIMjAqq1R
t2UP3f06/Zt7Jx5AxKqS4seFkaDlMAK8JkEDuMDOdKI36raHkKanfx8CnGMSNjFQ
QtvnpD8VSGkDTJN3Qs14vj2wvS477BQXkBKN1QIDAQABAoIBABb6xLMw9f+2ENyJ
hTggagXsxTjkS7TElCu2OFp1PpMfTAWl7oDBO7xi+UqvdCcVbHCD35hlWpqsC2Ui
8sBP46n040ts9UumK/Ox5FWaiuYMuDpF6vnfJ94KRcb0+KmeFVf9wpW9zWS0hhJh
jC+yfwpyfiOZ/ad8imGCaOguGHyYiiwbRf381T/1FlaOGSae88h+O8SKTG1Oahq4
0HZ/KBQf9pij0mfVQhYBzsNu2JsHNx9+DwJkrXT7K9SHBpiBAKisTTCnQmS89GtE
6J2+bq96WgugiM7X6OPnmBmE/q1TgV18OhT+rlvvNi5/n8Z1ag5Xlg1Rtq/bxByP
CeIVHsECgYEA9dX+LQdv/Mg/VGIos2LbpJUhJDj0XWnTRq9Kk2tVzr+9aL5VikEb
09UPIEa2ToL6LjlkDOnyqIMd/WY1W0+9Zf1ttg43S/6Rvv1W8YQde0Nc7QTcuZ1K
9jSSP9hzsa3KZtx0fCtvVHm+ac9fP6u80tqumbiD2F0cnCZcSxOb4+UCgYEAyAKJ
70nNKegH4rTCStAqR7WGAsdPE3hBsC814jguplCpb4TwID+U78Xxu0DQF8WtVJ10
SJuR0R2q4L9uYWpo0MxdawSK5s9Am27MtJL0mkFQX0QiM7hSZ3oqimsdUdXwxCGg
oktxCUUHDIPJNVd4Xjg0JTh4UZT6WK9hl1zLQzECgYEAiZRCFGc2KCzVLF9m0cXA
kGIZUxFAyMqBv+w3+zq1oegyk1z5uE7pyOpS9cg9HME2TAo4UPXYpLAEZ5z8vWZp
45sp/BoGnlQQsudK8gzzBtnTNp5i/MnnetQ/CNYVIVnWjSxRUHBqdMdRZhv0/Uga
e5KA5myZ9MtfSJA7VJTbyHUCgYBCcS13M1IXaMAt3JRqm+pftfqVs7YeJqXTrGs/
AiDlGQigRk4quFR2rpAV/3rhWsawxDmb4So4iJ16Wb2GWP4G1sz1vyWRdSnmOJGC
LwtYrvfPHegqvEGLpHa7UsgDpol77hvZriwXwzmLO8A8mxkeW5dfAfpeR5o+mcxW
pvnTEQKBgQCKx6Ln0ku6jDyuDzA9xV2/PET5D75X61R2yhdxi8zurY/5Qon3OWzk
jn/nHT3AZghGngOnzyv9wPMKt9BTHyTB6DlB6bRVLDkmNqZh5Wi8U1/IjyNYI0t2
xV/JrzLAwPoKk3bkqys3bUmgo6DxVC/6RmMwPQ0rmpw78kOgEej90g==
-----END RSA PRIVATE KEY-----
";

    /// The same shape, but passphrase-protected: nothing about it can be read
    /// without the passphrase, not even its algorithm beyond the header.
    const PEM_ENCRYPTED: &str = "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,EA77308AAF46981303D8C44D548D097E

QR18hXmAgGehm1QMMYGF34PAtBpTj+8/ZPFx2zZxir7pzDpfYoNAIf/fzLsW1ruG
0xo/ZK/T3/TpMgjmLsCR6q+KU4jmCcCqWQIGWYJt9ljFI5y/CXr5uqP3DKcqtdxQ
-----END RSA PRIVATE KEY-----
";

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("easyssh-keys-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn recognises_the_formats_a_private_key_arrives_in() {
        assert_eq!(detect_format(PEM_RSA), Some("PEM"));
        assert_eq!(detect_format(PEM_ENCRYPTED), Some("PEM"));
        assert_eq!(
            detect_format("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n"),
            Some("OpenSSH")
        );
        assert_eq!(
            detect_format("PuTTY-User-Key-File-3: ssh-ed25519\n"),
            Some("PuTTY")
        );
        assert_eq!(detect_format("ssh-ed25519 AAAA me@host\n"), None);
        assert_eq!(detect_format("Host example.com\n  User me\n"), None);
    }

    #[test]
    fn inspects_an_aws_style_pem() {
        let dir = tmpdir("inspect-pem");
        let path = dir.join("aws-key.pem");
        fs::write(&path, PEM_RSA).unwrap();

        let info = inspect(&path).expect("a .pem is a private key");
        assert_eq!(info.name, "aws-key.pem");
        assert_eq!(info.algorithm, "RSA");
        assert_eq!(info.format, "PEM");
        assert!(!info.encrypted);
        assert!(
            info.fingerprint.starts_with("SHA256:"),
            "a readable key should have a fingerprint, got {:?}",
            info.fingerprint
        );

        // And it must appear in the picker beside the OpenSSH keys.
        let listed = list_keys_in(&dir).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path, path.display().to_string());
    }

    #[test]
    fn lists_a_passphrase_protected_pem_it_cannot_read() {
        let dir = tmpdir("encrypted-pem");
        let path = dir.join("locked.pem");
        fs::write(&path, PEM_ENCRYPTED).unwrap();

        let info = inspect(&path).expect("an encrypted key is still a key");
        assert!(info.encrypted);
        assert_eq!(info.algorithm, "RSA");
        assert!(
            info.fingerprint.is_empty(),
            "nothing can be fingerprinted without the passphrase"
        );
    }

    #[test]
    fn derives_the_public_key_from_a_pem_with_no_pub_file() {
        let dir = tmpdir("pem-pub");
        let path = dir.join("aws-key.pem");
        fs::write(&path, PEM_RSA).unwrap();

        let line = authorized_keys_line(&path).expect("public half is derivable");
        assert!(line.starts_with("ssh-rsa "), "unexpected line: {line}");
    }

    #[test]
    fn importing_a_pem_copies_it_locks_it_down_and_writes_the_pub() {
        let downloads = tmpdir("import-src");
        let ssh_dir = tmpdir("import-dst");
        let source = downloads.join("ec2.pem");
        fs::write(&source, PEM_RSA).unwrap();
        // As downloaded from a browser: readable by everyone, which is exactly
        // what the system ssh refuses to use.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        }

        let info = import(&ssh_dir, &source).expect("import");
        let dest = ssh_dir.join("ec2.pem");
        assert_eq!(info.path, dest.display().to_string());
        assert_eq!(fs::read_to_string(&dest).unwrap(), PEM_RSA);
        assert!(
            fs::read_to_string(pub_path_for(&dest))
                .unwrap()
                .starts_with("ssh-rsa "),
            "a .pem has no .pub of its own; one must be derived"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the imported key must be owner-only");
        }

        // Importing the same key again is how permissions get fixed: no error.
        import(&ssh_dir, &source).expect("re-import");

        // A different key under a name already taken must not be overwritten.
        let elsewhere = tmpdir("import-src2");
        let other = elsewhere.join("ec2.pem");
        fs::write(&other, PEM_ENCRYPTED).unwrap();
        let err = import(&ssh_dir, &other).expect_err("must refuse to clobber");
        assert!(
            err.to_string().contains("already in"),
            "unhelpful error: {err}"
        );
        assert_eq!(fs::read_to_string(&dest).unwrap(), PEM_RSA);
    }

    #[test]
    fn refuses_to_import_something_that_is_not_a_key() {
        let dir = tmpdir("import-junk");
        let src = dir.join("notes.txt");
        fs::write(&src, "ssh-ed25519 AAAA me@host\n").unwrap();
        assert!(import(&dir.join("dest"), &src).is_err());
    }
}
