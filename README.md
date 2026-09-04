<div align="center">

# easySSH

**Connect once with a password. Never type it again.**

easySSH sets up key-based login for you, opens a real terminal already
connected, and brings the server's web apps to your browser.

macOS · Windows · built in Rust

</div>

---

## The problem it solves

You have a new server. Normally that means: `ssh-keygen`, `ssh-copy-id`, hope
the permissions are right, edit `~/.ssh/config`, remember which port that
dashboard is on, then `ssh -L 8080:localhost:3000 …` every single time.

easySSH does all of that from one window.

| Instead of | You do |
| --- | --- |
| `ssh-keygen` + `ssh-copy-id` + fixing `authorized_keys` permissions | Type your password once, click **Set Up** |
| `ssh -L 8080:localhost:3000 user@host` and remembering ports | Flip a switch, click **Open** |
| Editing `~/.ssh/config` by hand | Click **Add to Config** |
| `vim ~/.ssh/known_hosts` after a server rebuild | Select the entry, click **Remove** |

---

## Quick start

**1 · Install.** Grab the installer for your platform from
[Releases](../../releases) — `.dmg` for macOS, `.exe` or `.msi` for Windows.
Or [build it yourself](#building-from-source) in one command.

> On macOS, an unsigned build needs a right-click → **Open** the first time.
> That is Gatekeeper doing its job on software without an Apple certificate.

**2 · Your servers are already there.** If you have a `~/.ssh/config`, every
`Host` in it appears in the sidebar the moment you open the app, tagged `cfg`.
Nothing to import. If you don't, click **New Connection** and enter the host,
user, and port.

**3 · Set up passwordless login.** Select a connection and click **Set Up…**
under *Authentication*. Enter your password one time. easySSH will:

- generate an Ed25519 key if you don't have one (or use the key you pick)
- append the public key to `~/.ssh/authorized_keys` on the server
- fix the directory and file permissions, and the SELinux label if there is one
- **log in again with the key to prove it worked**

That last step matters. If the server has `PubkeyAuthentication` turned off, or
the home directory is read-only, you find out immediately — not the next time
you try to connect.

**4 · Connect.** Click **Connect**. From here you can:

- **Terminal** — opens iTerm or Terminal.app (macOS) or Windows Terminal, with
  the session already live. Your shell, your colours, your scrollback, your tmux.
- **Web tunnels** — add one, flip it on, click **Open**. The server's dashboard
  appears in your browser as though it were running locally.
- **Run a command** — a quick one-off without leaving the app. Shows stdout,
  stderr, and the exit status.

---

## Status at a glance

Every connection carries four lamps, in the sidebar and on its detail page.
easySSH keeps them current in the background, so you can see the state of your
fleet without clicking into anything.

| Lamp | Green | Blue | Red | Grey |
| --- | --- | --- | --- | --- |
| **Session** | connected now | — | — | not connected |
| **Reachable** | — | the SSH port answers | nothing answered | not checked yet |
| **Key login** | logs in without a password | — | the key was refused | unknown |
| **Tunnels** | at least one is up | — | all down, or **blinking** on an error | no tunnels defined |

Reachability is a TCP connect to the SSH port, not an ICMP ping: it needs no
special privileges, behaves the same on macOS and Windows, and tests the port
that actually matters. It runs every 45 seconds.

Key login is a real handshake, so it is far more expensive — it runs at most
every five minutes, only when no session is already open (a live connection
proves the answer anyway), and it **backs off** after failures, up to an hour.
That last part matters: a key that is genuinely rejected would otherwise
generate a failed authentication every five minutes forever, which is exactly
the pattern fail2ban exists to ban. Background probes also refuse to trust a
host that is not already in `known_hosts`, so easySSH never pins a host key
without showing you the fingerprint first.

---

## Web tunnels, and why the remote address matters

A tunnel forwards a port on your machine to an address **the server can reach**:

```
127.0.0.1:8080   →   localhost:3000     the server's own web app
127.0.0.1:8081   →   10.0.0.9:8443      a box on the server's private network
127.0.0.1:5433   →   db.internal:5432   anything its DNS resolves
```

The remote address is resolved *on the server*, not here. That is what lets you
reach a service bound to the server's loopback interface, or a machine that has
no route from your laptop at all.

Mark a tunnel **auto-start** and it comes up the moment you connect.

---

## Working with your ssh config

easySSH treats `~/.ssh/config` as the source of truth, not a one-time import.

- **Choose which config.** The picker at the bottom of the sidebar lists every
  `.ssh` location it found, with the number of keys and hosts in each. Switch
  between them freely; your choice is remembered.
- **Hosts appear automatically.** Every `Host` block becomes a connection,
  tagged `cfg`, with the key from its `IdentityFile` already selected.
  `Include` directives and `Host *` defaults are followed.
- **Delete a `Host` block and the connection disappears** from easySSH too.
- **Edits show up while the app is open.** easySSH watches the config file, so
  a `Host` block you add or remove in your editor appears or disappears within a
  couple of seconds — no restart.
- **Edit one and it becomes yours.** Changing settings or adding a tunnel makes
  it a saved connection that the config no longer governs — so your work is
  never silently rebuilt away.
- **Add a server to the config.** Click **Add to Config** and easySSH writes a
  `Host` block with `IdentityFile` and `LocalForward` lines filled in, so plain
  `ssh myserver` works from any terminal afterwards. Existing blocks are never
  rewritten.

### Where it looks

| Platform | Locations searched |
| --- | --- |
| macOS / Linux | `~/.ssh`, `/etc/ssh` |
| Windows | `~/.ssh`, `%USERPROFILE%\.ssh`, `%ProgramData%\ssh`, Git for Windows' `etc\ssh` |

Set `EASYSSH_SSH_DIR` to put a directory of your own at the top of the list.

---

## Keys and known hosts

**Keys.** Pick one from the selected `.ssh` directory, browse to one anywhere on
disk, or generate a new Ed25519 or RSA pair. New keys are written with
owner-only permissions — `0600` on Unix, and inherited ACEs stripped on Windows,
which is what OpenSSH there insists on. View or copy any public key from the key
icon in the sidebar.

**Known hosts.** The shield icon opens an editor for `known_hosts`, showing each
entry's host, algorithm, fingerprint, and which of your connections depend on
it. `@revoked` and `@cert-authority` markers and hashed entries are called out;
lines it cannot parse are still listed, so nothing in the file is invisible to
you.

Reach for it when a server has been rebuilt and easySSH refuses to connect
because the host key changed. The file is backed up before every edit, and a
removal is refused outright if the file changed since the list was loaded.

---

## How it handles your credentials

- **Passwords are never written to disk.** They are held only for the length of
  a single connection or key install. `profiles.json` has no field for one.
- **Host keys are pinned.** Trust-on-first-use: an unknown host is accepted,
  recorded, and its fingerprint shown to you. A host whose key has *changed* is
  **refused** — that is what a man-in-the-middle looks like.
- **Only local forwarded ports open in your browser.** The Open button rejects
  any URL that is not `127.0.0.1`.
- **The system `ssh` does the terminal work.** easySSH hands it a command; it
  never proxies your interactive session.

Settings live in `~/Library/Application Support/easySSH/` on macOS and
`%APPDATA%\easySSH\` on Windows.

---

## Building from source

You need [Rust](https://rustup.rs). The scripts install everything else.

```bash
git clone https://github.com/leondavi/easySSH.git
cd easySSH

./scripts/build.sh              # bundle for the machine you are on
./scripts/build.sh macos        # .dmg + .app
./scripts/build.sh --universal  # one .dmg for Apple Silicon and Intel
```

On Windows, in PowerShell:

```powershell
.\scripts\build.ps1             # .exe (NSIS) + .msi
.\scripts\build.ps1 -Bundles nsis
```

Installers land in `src-tauri/target/release/bundle/`.

**Each platform's installer must be built on that platform.** A `.dmg` needs
Apple's tooling and `.exe`/`.msi` need NSIS and WiX. To get both at once, push a
tag — `.github/workflows/release.yml` builds macOS (both architectures) and
Windows and collects them into a draft release.

For development:

```bash
cargo tauri dev
```

### Signing

`build.sh` ad-hoc signs the `.app` so it runs on the machine that built it.
Shipping to other people needs a Developer ID certificate and notarisation: set
`APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD` and `APPLE_TEAM_ID`, or
add them as repository secrets for the release workflow.

---

## Contributing

```bash
cd src-tauri
cargo test           # 41 tests, including a real SSH server harness
cargo clippy --all-targets -- -D warnings
cargo fmt
```

CI runs tests on macOS and Windows, checks the UI wiring, and **builds the
Windows installers on every push** — the Windows code paths cannot be compiled
on a Mac, so that job is what proves they work.

`testserver.rs` is a real SSH server used by the tests, so the parts that matter
most are exercised rather than merely read: authenticating, forwarding a port
end to end, and running the `authorized_keys` script under a real shell with
`HOME` pointed at a throwaway directory — which checks the resulting file
permissions and that a second run does not duplicate the key.

### Layout

```
src-tauri/src/
  main.rs        window setup and command registration
  commands.rs    the API the UI calls
  ssh.rs         connecting, running commands, installing the public key
  tunnels.rs     local port forwarding
  sshconfig.rs   .ssh discovery and the ssh_config parser
  knownhosts.rs  reading and editing known_hosts
  keys.rs        key discovery, inspection and generation
  terminal.rs    handing an ssh command to the platform's terminal
  probe.rs       background reachability and key-login checks
  testserver.rs  a real SSH server, for tests
  store.rs       profiles.json and settings.json
  state.rs       live sessions, tunnels, and config-derived connections
  model.rs       types shared with the UI

ui/              front end — plain HTML, CSS and JS, no build step
scripts/         build.sh (macOS/Linux) and build.ps1 (Windows)
```

Built with [Tauri 2](https://tauri.app) and
[russh](https://github.com/warp-tech/russh) — a pure-Rust SSH implementation, so
there is no OpenSSL or libssh2 to install.

---

## Licence

See [LICENSE](LICENSE).
