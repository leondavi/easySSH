<div align="center">

# easySSH

**Connect once with a password. Never type it again.**

easySSH sets up key-based login for you, opens a real terminal already
connected, and brings the server's web apps to your browser.

macOS · Windows · Debian/Ubuntu · built in Rust

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
| `chmod 600 aws-key.pem` and `ssh -i … ec2-user@…` | **Browse…** to the `.pem`, click **Connect** |
| `chmod 600 ~/.ssh/that-key` after ssh refuses it | easySSH marks it and fixes it for you |

---

## Quick start

**1 · Install.** Grab the installer for your platform from
[Releases](../../releases) — `.dmg` for macOS, `.exe` or `.msi` for Windows,
`.deb` for Debian and Ubuntu. Or [build it yourself](#building-from-source) in
one command.

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

- **Terminal** — opens iTerm or Terminal.app (macOS), Windows Terminal, or
  your `x-terminal-emulator` (Debian/Ubuntu), with the session already live.
  Your shell, your colours, your scrollback, your tmux.
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

## Connecting to AWS EC2

An EC2 instance has no password login at all: the key pair you chose when you
launched it is the only way in. AWS gives you that key once, as a `.pem` in your
downloads folder — world-readable, which is exactly the thing the system `ssh`
refuses to touch.

**Browse…**, beside the key picker, deals with all of it. Point it at the file
you downloaded and easySSH works out what it is: a world-readable `.pem` is
copied into your `.ssh` directory at `0600` — the permissions the system `ssh`
insists on — and the public half, which a `.pem` arrives without, is derived
and written to a `.pub` beside it. From then on it behaves like any other key
here: selectable for any connection, written as an `IdentityFile` into
`ez_config`, and usable by `ssh` from any terminal.

The rest is the host name and the user, and easySSH recognises an EC2 address:
type one into **New Connection** and it switches to key authentication, fills
in `ec2-user`, and lists the alternatives, because the user name comes from the
image rather than from anything visible in the address:

| Image | User |
| --- | --- |
| Amazon Linux | `ec2-user` |
| Ubuntu | `ubuntu` |
| Debian | `admin` |
| CentOS / Rocky / Fedora | `centos`, `rocky`, `fedora` |
| Bitnami | `bitnami` |

There is no **Set Up…** step to run: AWS already put your public key in the
instance's `authorized_keys`. Connect, and the tunnels and terminal work as they
do for anything else.

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

Mark a tunnel **auto-start** and it comes up the moment you connect. Add or
edit one while the connection is already open and easySSH starts it there and
then, so it never sits idle waiting for a reconnect. The switch beside each
tunnel turns it on and off by hand.

---

## Working with your ssh config

Your config and easySSH's own connections are kept apart:

- `~/.ssh/config` is **yours**. easySSH reads it, and never writes to it beyond
  a single `Include ez_config` line at the top.
- `~/.ssh/ez_config` is **easySSH's**, in the same directory and the same
  OpenSSH syntax, with `IdentityFile` and `LocalForward` lines filled in — so
  every connection you save here also works as plain `ssh <alias>` from any
  terminal. The few things ssh config cannot express (colours, tunnel names and
  schemes) sit beside it in `ez_config.json`.

Both live wherever the `.ssh` directory you have selected is, so a connection
travels with the keys it uses.

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
- **Import one and it becomes yours.** **Import** on a `cfg` connection — or
  simply editing it, or adding a tunnel — copies it into `ez_config`, where the
  config no longer governs it and your work is never silently rebuilt away.
  Your own config file keeps its `Host` block untouched.
- **Hide them.** Untick *Show hosts from this config* under the picker to leave
  only the connections easySSH owns. A host you are connected to stays listed.
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

**Browse… figures out what you picked.** A key does not have to be in the
format `ssh-keygen` writes: easySSH reads PEM — PKCS#1, PKCS#8 and their
encrypted forms, which is what AWS gives you — and PuTTY's `.ppk`, and lists
them in the picker with the format named beside the algorithm. It also sorts
out the things that are easy to get wrong:

- **Picked the public half?** `id_ed25519.pub` resolves to `id_ed25519` beside
  it. A `.pub` with no private key next to it says so, rather than failing later
  at connect time.
- **Permissions ssh would refuse** are tightened to `0600` where the key lies,
  or, for a key outside your `.ssh` directory — a fresh download — the key is
  copied in at `0600` and that copy is used. Keys already private are left
  exactly where you keep them.
- **No `.pub` beside it?** One is derived, so the key can be installed on other
  servers and shown in the public key viewer.

A passphrase-protected PEM is listed even though nothing about it can be read
until you type the passphrase.

**A key that goes loose later is caught too.** Browse… is not the only way a key
arrives in `~/.ssh`: they get dragged in from the Finder, restored from backups,
unzipped, copied off another machine — and they keep the permissions they had.
easySSH connects through its own SSH client, which does not look at mode bits at
all, so such a key works here and then fails in the terminal, with an error that
comes from `ssh` rather than from easySSH:

```
WARNING: UNPROTECTED PRIVATE KEY FILE!
Permissions 0644 for '/Users/you/.ssh/cells-app.pem' are too open.
This private key will be ignored.
```

So the key picker marks any key `ssh` would refuse and offers **Fix
permissions** beside it, and every route that leads to a key actually being used
— connecting, installing it on a server, opening a terminal — tightens it to
`0600` first and says what it did. You should never have to reach for `chmod`.

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
  a single connection or key install. `ez_config` has no field for one.
- **Host keys are pinned.** Trust-on-first-use: an unknown host is accepted,
  recorded, and its fingerprint shown to you. A host whose key has *changed* is
  **refused** — that is what a man-in-the-middle looks like.
- **Only local forwarded ports open in your browser.** The Open button rejects
  any URL that is not `127.0.0.1`.
- **The system `ssh` does the terminal work.** easySSH hands it a command; it
  never proxies your interactive session.

Connections live in `ez_config` in your `.ssh` directory, 0600 like everything
else there. Only app settings — which `.ssh` directory is in focus — stay in
`~/Library/Application Support/easySSH/` on macOS, `%APPDATA%\easySSH\` on
Windows and `~/.config/easySSH/` on Linux. Connections saved by earlier versions are moved out of `profiles.json`
into `ez_config` the first time you run this one.

---

## Building from source

You need [Rust](https://rustup.rs). The scripts install everything else.

```bash
git clone https://github.com/leondavi/easySSH.git
cd easySSH

./scripts/build.sh              # bundle for the machine you are on
./scripts/build.sh macos        # .dmg + .app
./scripts/build.sh linux        # .deb, on Debian or Ubuntu
./scripts/build.sh --universal  # one .dmg for Apple Silicon and Intel
```

On Debian or Ubuntu the bundler needs the system web view's development
packages — easySSH draws in WebKitGTK rather than shipping a browser:

```bash
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev \
  libssl-dev libayatana-appindicator3-dev patchelf build-essential
```

`build.sh linux` checks for these and names the missing ones rather than
letting the linker fail three minutes in.

On Windows, in PowerShell:

```powershell
.\scripts\build.ps1             # .exe (NSIS) + .msi
.\scripts\build.ps1 -Bundles nsis
```

Installers land in `src-tauri/target/release/bundle/`.

**Each platform's installer must be built on that platform.** A `.dmg` needs
Apple's tooling, `.exe`/`.msi` need NSIS and WiX, and a `.deb` needs the GTK
and WebKit libraries it links against. To get all of them at once, push a tag —
`.github/workflows/release.yml` builds macOS (both architectures), Windows and
Debian/Ubuntu and collects them into a draft release. The `.deb` is built on
Ubuntu 22.04, since a package links against the glibc it was built on and the
oldest supported release is the one that installs everywhere.

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
cargo test           # 59 tests, including a real SSH server harness
cargo clippy --all-targets -- -D warnings
cargo fmt
```

CI runs tests on macOS, Windows and Ubuntu, checks the UI wiring, and **builds
the Windows installers and the Linux `.deb` on every push** — those platforms'
code paths cannot be compiled on a Mac, so those jobs are what prove they work.

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
  ezconfig.rs    the ez_config connection store in ~/.ssh
  store.rs       app settings, and the move off the old profiles.json
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
