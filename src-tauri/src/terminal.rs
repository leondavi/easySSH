//! Hand an already-configured `ssh` command to the platform's terminal app.
//!
//! We shell out to the system `ssh` rather than embedding a terminal emulator:
//! it gives you the real thing — your shell, your colours, scrollback, tmux —
//! and it reuses the key easySSH just installed.

use std::process::Command;

use anyhow::Result;

use crate::model::{AuthMethod, Profile, TerminalApp};

/// Build the argument list for `ssh`, including any tunnels the profile defines.
///
/// `already_forwarded` names the local ports easySSH is forwarding itself.
/// Handing those to `ssh -L` as well would have two processes racing for the
/// same loopback port: whichever binds first wins, and the other reports the
/// port as busy even though the forward the user wanted is already up.
pub fn ssh_args(
    profile: &Profile,
    include_tunnels: bool,
    already_forwarded: &[u16],
) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();

    if profile.port != 22 {
        args.push("-p".into());
        args.push(profile.port.to_string());
    }

    if profile.auth == AuthMethod::Key {
        if let Some(path) = &profile.key_path {
            args.push("-i".into());
            args.push(path.clone());
            // Use exactly the key we were given, not whatever the agent offers first.
            args.push("-o".into());
            args.push("IdentitiesOnly=yes".into());
        }
    }

    if include_tunnels {
        for t in &profile.tunnels {
            if already_forwarded.contains(&t.local_port) {
                continue;
            }
            args.push("-L".into());
            args.push(format!(
                "127.0.0.1:{}:{}:{}",
                t.local_port, t.remote_host, t.remote_port
            ));
        }
    }

    args.push(profile.target());
    args
}

/// A single command line, quoted for the shell that will receive it.
pub fn ssh_command_line(
    profile: &Profile,
    include_tunnels: bool,
    already_forwarded: &[u16],
) -> String {
    let mut parts = vec!["ssh".to_string()];
    parts.extend(
        ssh_args(profile, include_tunnels, already_forwarded)
            .into_iter()
            .map(|a| quote(&a)),
    );
    parts.join(" ")
}

/// True for arguments that need no quoting on any of our target shells.
fn is_plain(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "@%_+=:,./-".contains(c))
}

/// cmd.exe does not treat `'` as a quote character, so a POSIX-quoted path
/// would reach ssh with the quotes still attached. Use `"` there instead.
#[cfg(target_os = "windows")]
fn quote(s: &str) -> String {
    if is_plain(s) {
        return s.to_string();
    }
    // Backslashes are path separators here, not escapes, so they pass through.
    format!("\"{}\"", s.replace('"', ""))
}

/// POSIX single-quote escaping.
#[cfg(not(target_os = "windows"))]
fn quote(s: &str) -> String {
    if is_plain(s) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// AppleScript string literal escaping.
#[cfg(target_os = "macos")]
fn applescript_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
}

/// Open the user's terminal with the SSH session already running.
///
/// `preferred` is the terminal picked in settings, by the id [`available`]
/// gave it. `None` — or a choice that has since been uninstalled — leaves the
/// pick to easySSH, which is how the button behaved before there was a choice.
pub fn open(
    profile: &Profile,
    include_tunnels: bool,
    already_forwarded: &[u16],
    preferred: Option<&str>,
) -> Result<String> {
    let command = ssh_command_line(profile, include_tunnels, already_forwarded);
    let preferred = preferred.filter(|id| available().iter().any(|t| t.id == *id));
    launch(&command, preferred)?;
    Ok(command)
}

/// What the terminal runs: the ssh command, then a shell once it exits.
///
/// Dropping into a shell instead of closing the window with ssh is what
/// `cmd /K` does on Windows and what Terminal.app does on macOS, and it is the
/// difference between reading why a connection failed and watching the window
/// vanish.
#[cfg(unix)]
fn shell_script(command: &str) -> String {
    format!("{command}; exec ${{SHELL:-sh}}")
}

/// Whether `bin` is an executable on `$PATH`. A path is checked as given.
#[cfg(unix)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn on_path(bin: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    let runnable = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    if bin.contains('/') {
        return runnable(Path::new(bin));
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir: PathBuf| runnable(&dir.join(bin))))
        .unwrap_or(false)
}

// ------------------------------------------------------------------ macOS

/// The terminals easySSH can drive on macOS: id, name, app bundle.
#[cfg(target_os = "macos")]
const MAC_APPS: &[(&str, &str, &str)] = &[
    ("terminal", "Terminal", "Terminal.app"),
    ("iterm", "iTerm2", "iTerm.app"),
    ("ghostty", "Ghostty", "Ghostty.app"),
    ("wezterm", "WezTerm", "WezTerm.app"),
    ("alacritty", "Alacritty", "Alacritty.app"),
    ("kitty", "kitty", "kitty.app"),
];

/// Where an app bundle is installed, if it is.
#[cfg(target_os = "macos")]
fn app_bundle(bundle: &str) -> Option<std::path::PathBuf> {
    use std::path::PathBuf;

    let mut dirs = vec![
        PathBuf::from("/Applications"),
        PathBuf::from("/Applications/Utilities"),
        PathBuf::from("/System/Applications/Utilities"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join("Applications"));
    }
    dirs.into_iter()
        .map(|d| d.join(bundle))
        .find(|p| p.is_dir())
}

/// The terminals installed on this machine, for the settings menu.
#[cfg(target_os = "macos")]
pub fn available() -> Vec<TerminalApp> {
    MAC_APPS
        .iter()
        .filter(|(_, _, bundle)| app_bundle(bundle).is_some())
        .map(|(id, name, _)| TerminalApp {
            id: id.to_string(),
            name: name.to_string(),
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn terminal_app_script(cmd: &str) -> String {
    format!(
        r#"tell application "Terminal"
    activate
    do script {cmd}
end tell"#
    )
}

#[cfg(target_os = "macos")]
fn iterm_script(cmd: &str) -> String {
    format!(
        r#"tell application "iTerm"
    activate
    try
        tell current window to create tab with default profile
    on error
        create window with default profile
    end try
    tell current session of current window to write text {cmd}
end tell"#
    )
}

#[cfg(target_os = "macos")]
fn osascript(script: &str) -> bool {
    Command::new("osascript")
        .arg("-e")
        .arg(script)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn launch(command: &str, preferred: Option<&str>) -> Result<()> {
    use anyhow::anyhow;

    let cmd = applescript_quote(command);
    let opened = match preferred {
        // Prefer iTerm when the user has it open, then fall back to Terminal.app.
        None => osascript(&format!(
            "if application \"iTerm\" is running then\n{}\nelse\n{}\nend if",
            iterm_script(&cmd),
            terminal_app_script(&cmd)
        )),
        Some("terminal") => osascript(&terminal_app_script(&cmd)),
        Some("iterm") => osascript(&iterm_script(&cmd)),
        Some(id) => launch_mac_app(id, command),
    };
    if opened {
        return Ok(());
    }

    // The chosen app may be installed but scriptably unhappy; Terminal.app is
    // the safe floor.
    if osascript(&terminal_app_script(&cmd)) {
        return Ok(());
    }
    Err(anyhow!("macOS refused to open Terminal"))
}

/// Start one of the terminals that take the command on their command line
/// rather than through AppleScript.
#[cfg(target_os = "macos")]
fn launch_mac_app(id: &str, command: &str) -> bool {
    let Some(bundle) = MAC_APPS
        .iter()
        .find(|(i, _, _)| *i == id)
        .and_then(|(_, _, b)| app_bundle(b))
    else {
        return false;
    };
    let binary = |name: &str| Command::new(bundle.join("Contents/MacOS").join(name));
    let script = shell_script(command);

    let mut cmd = match id {
        // Ghostty will not open a window when its binary is started directly
        // on macOS; it has to come up through Launch Services.
        "ghostty" => {
            let mut c = Command::new("open");
            c.arg("-na").arg(&bundle).args(["--args", "-e"]);
            c
        }
        "wezterm" => {
            let mut c = binary("wezterm");
            c.args(["start", "--"]);
            c
        }
        "alacritty" => {
            let mut c = binary("alacritty");
            c.arg("-e");
            c
        }
        "kitty" => binary("kitty"),
        _ => return false,
    };
    cmd.args(["sh", "-c", &script]);
    cmd.spawn().map(started).unwrap_or(false)
}

// ---------------------------------------------------------------- Windows

/// The terminals easySSH can drive on Windows: id, name.
#[cfg(target_os = "windows")]
const WINDOWS_TERMINALS: &[(&str, &str)] = &[
    ("wt", "Windows Terminal"),
    ("cmd", "Command Prompt"),
    ("powershell", "Windows PowerShell"),
    ("pwsh", "PowerShell 7"),
];

/// Whether `exe` is on `%PATH%`.
///
/// `symlink_metadata`, not `exists`: wt.exe is an app execution alias, a
/// reparse point that following would fail on even though it runs fine.
#[cfg(target_os = "windows")]
fn on_path(exe: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .any(|dir| std::fs::symlink_metadata(dir.join(exe)).is_ok())
        })
        .unwrap_or(false)
}

/// The terminals installed on this machine, for the settings menu.
#[cfg(target_os = "windows")]
pub fn available() -> Vec<TerminalApp> {
    WINDOWS_TERMINALS
        .iter()
        .filter(|(id, _)| match *id {
            "wt" => on_path("wt.exe"),
            "pwsh" => on_path("pwsh.exe"),
            // Part of Windows itself.
            _ => true,
        })
        .map(|(id, name)| TerminalApp {
            id: id.to_string(),
            name: name.to_string(),
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn launch(command: &str, preferred: Option<&str>) -> Result<()> {
    use anyhow::Context as _;
    use std::os::windows::process::CommandExt;

    /// Give the spawned shell its own console. easySSH is a windows-subsystem
    /// binary with no console of its own, so without this the shell would have
    /// nowhere to draw.
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

    // `spawn`, not `status`: the terminal stays open for as long as the user
    // wants it, and waiting on it would block the command that opened it.
    let console = |exe: &str, args: &[&str]| {
        Command::new(exe)
            .args(args)
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn()
            .is_ok()
    };

    let opened = match preferred {
        Some("cmd") => console("cmd", &["/K", command]),
        // The command is quoted with `"`, which PowerShell reads the same way.
        Some(ps @ ("powershell" | "pwsh")) => console(ps, &["-NoExit", "-Command", command]),
        // Windows Terminal gives tabs and a modern renderer. Spawning it
        // directly rather than through `cmd /C start` means a missing wt.exe
        // surfaces as a plain NotFound error instead of a shell quoting puzzle.
        _ => Command::new("wt.exe")
            .args(["cmd", "/K", command])
            .spawn()
            .is_ok(),
    };
    if opened {
        return Ok(());
    }

    Command::new("cmd")
        .args(["/K", command])
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .context("starting cmd.exe")?;

    Ok(())
}

// ------------------------------------------------------- Linux and the BSDs

/// The terminals easySSH knows, in the order it tries them: the binary, what
/// the settings menu calls it, and the arguments that make it run a command.
/// The flag is not interchangeable between families: several of these accept
/// the wrong one, open, and then run nothing.
#[cfg(unix)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
const TERMINALS: &[(&str, &str, &[&str])] = &[
    // The freedesktop launcher: it resolves the user's configured terminal
    // itself, so where it exists it is more likely right than our guesses.
    (
        "xdg-terminal-exec",
        "System default (xdg-terminal-exec)",
        &[],
    ),
    // Debian's alternatives entry — on Debian and Ubuntu this is whatever
    // terminal the user actually chose.
    (
        "x-terminal-emulator",
        "Debian default (x-terminal-emulator)",
        GENERIC,
    ),
    // GTK family. `-e` is deprecated in these and takes a single string,
    // so it would swallow `sh` and leave `-c` behind as an unknown option;
    // `--` ends option parsing and passes the argv through intact.
    ("gnome-terminal", "GNOME Terminal", &["--"]),
    ("kgx", "GNOME Console", &["--"]),
    ("ptyxis", "Ptyxis", &["--"]),
    ("mate-terminal", "MATE Terminal", &["--"]),
    // These spell the same idea `-x`: everything after it is the command.
    ("xfce4-terminal", "Xfce Terminal", &["-x"]),
    ("terminator", "Terminator", &["-x"]),
    ("tilix", "Tilix", &["-e"]),
    ("konsole", "Konsole", GENERIC),
    ("qterminal", "QTerminal", GENERIC),
    ("deepin-terminal", "Deepin Terminal", GENERIC),
    ("alacritty", "Alacritty", GENERIC),
    ("wezterm", "WezTerm", &["start", "--"]),
    // kitty and foot take the command straight after their own options,
    // with no flag introducing it.
    ("kitty", "kitty", &[]),
    ("foot", "foot", &[]),
    ("urxvt", "rxvt-unicode", GENERIC),
    ("rxvt", "rxvt", GENERIC),
    ("st", "st", GENERIC),
    ("xterm", "xterm", GENERIC),
];

/// `-e` is the flag Debian policy requires of a terminal emulator, so it is
/// the right guess for one we were told about but know nothing else of.
#[cfg(unix)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
const GENERIC: &[&str] = &["-e"];

/// The terminals installed on this machine, for the settings menu.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn available() -> Vec<TerminalApp> {
    TERMINALS
        .iter()
        .filter(|(bin, _, _)| on_path(bin))
        .map(|(bin, name, _)| TerminalApp {
            id: bin.to_string(),
            name: name.to_string(),
        })
        .collect()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn launch(command: &str, preferred: Option<&str>) -> Result<()> {
    use anyhow::anyhow;

    let script = shell_script(command);

    let mut tried: Vec<String> = Vec::new();
    for (bin, prefix) in candidates(preferred) {
        let mut cmd = Command::new(&bin);
        cmd.args(&prefix).arg("sh").arg("-c").arg(&script);
        let Ok(child) = cmd.spawn() else {
            continue; // not installed
        };
        if started(child) {
            return Ok(());
        }
        tried.push(bin);
    }

    if tried.is_empty() {
        return Err(anyhow!(
            "no terminal emulator found. Install one — on Debian or Ubuntu, \
             `sudo apt-get install gnome-terminal` — set $TERMINAL to the one \
             you prefer, or copy the command above and run it yourself."
        ));
    }
    Err(anyhow!(
        "{} would not open. Choose another terminal under the Terminal card, \
         set $TERMINAL to the one you use, or copy the command above and run \
         it yourself.",
        tried.join(", ")
    ))
}

/// The arguments that make `term` run a command. It may be given as a path,
/// and is recognised by name either way; one we do not know gets `-e`.
#[cfg(unix)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn args_for(term: &str) -> Vec<String> {
    let name = std::path::Path::new(term)
        .file_name()
        .and_then(|f| f.to_str());
    TERMINALS
        .iter()
        .find(|(bin, _, _)| Some(*bin) == name)
        .map(|(_, _, args)| *args)
        .unwrap_or(GENERIC)
        .iter()
        .map(|a| a.to_string())
        .collect()
}

/// The terminals to try, in order, each with the arguments that make it run a
/// command: the one chosen in settings, then `$TERMINAL`, then every one we
/// know, so a choice that will not open still leaves the user a window.
///
/// Built on every unix, not only where it is used: this is the one launcher
/// with no OS API to lean on, and compiling it on macOS too means its tests
/// run wherever they are run at all.
#[cfg(unix)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn candidates(preferred: Option<&str>) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let mut push = |term: &str| {
        let term = term.trim();
        if !term.is_empty() && !out.iter().any(|(b, _)| b == term) {
            out.push((term.to_string(), args_for(term)));
        }
    };

    // An explicit choice beats anything we would work out for ourselves.
    if let Some(term) = preferred {
        push(term);
    }
    if let Ok(term) = std::env::var("TERMINAL") {
        push(&term);
    }
    for (bin, _, _) in TERMINALS {
        push(bin);
    }
    out
}

/// Whether a spawned terminal actually opened.
///
/// Spawning only proves the binary exists and forked. A terminal handed a flag
/// it does not understand prints a usage message and exits within moments, and
/// treating that as success is how easySSH could report an open terminal while
/// the user saw no window at all — with the remaining candidates never tried.
#[cfg(unix)]
fn started(mut child: std::process::Child) -> bool {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_millis(400);
    loop {
        match child.try_wait() {
            // Still up after the grace period: the window is the user's now.
            Ok(None) if Instant::now() >= deadline => {
                // Reap it in the background rather than leaving a zombie
                // behind for as long as easySSH keeps running.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return true;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            // gnome-terminal and its relatives hand the window to a session
            // daemon and exit at once, so a zero status here is a success too.
            Ok(Some(status)) => return status.success(),
            Err(_) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Tunnel;

    fn profile_with_tunnels(ports: &[u16]) -> Profile {
        let mut p = Profile {
            id: "p1".into(),
            name: "Server".into(),
            host: "example.com".into(),
            port: 22,
            username: "david".into(),
            auth: AuthMethod::Password,
            key_path: None,
            tunnels: Vec::new(),
            last_connected: None,
            color: None,
            key_installed: false,
            from_config: false,
            config_alias: None,
            customized: true,
        };
        p.tunnels = ports
            .iter()
            .map(|port| Tunnel {
                id: format!("t{port}"),
                name: format!("Port {port}"),
                local_port: *port,
                remote_host: "localhost".into(),
                remote_port: *port,
                auto_start: true,
                scheme: "http".into(),
            })
            .collect();
        p
    }

    #[test]
    fn tunnels_become_local_forwards() {
        let cmd = ssh_command_line(&profile_with_tunnels(&[4000, 5000]), true, &[]);
        assert!(cmd.contains("-L 127.0.0.1:4000:localhost:4000"), "{cmd}");
        assert!(cmd.contains("-L 127.0.0.1:5000:localhost:5000"), "{cmd}");
    }

    /// The terminal must not race easySSH for a port easySSH already holds:
    /// only one process can bind it, and the loser reports the port as busy
    /// while the forward the user wanted is in fact already up.
    #[test]
    fn a_port_easyssh_already_forwards_is_left_to_it() {
        let cmd = ssh_command_line(&profile_with_tunnels(&[4000, 5000]), true, &[4000]);
        assert!(!cmd.contains("127.0.0.1:4000"), "{cmd}");
        assert!(cmd.contains("-L 127.0.0.1:5000:localhost:5000"), "{cmd}");
    }

    /// The GTK terminals must not be handed `-e`: it is deprecated there and
    /// takes a single string, so `-e sh -c <script>` runs `sh` with no script
    /// and leaves `-c` behind as an unknown option.
    #[cfg(unix)]
    #[test]
    fn the_gtk_terminals_get_argv_passed_through_not_a_deprecated_flag() {
        let all = candidates(None);
        for name in ["gnome-terminal", "kgx", "ptyxis", "mate-terminal"] {
            let args = all
                .iter()
                .find(|(bin, _)| bin == name)
                .map(|(_, a)| a.clone())
                .unwrap_or_else(|| panic!("{name} is not among the candidates"));
            assert_eq!(args, vec!["--".to_string()], "{name}");
        }
    }

    /// Whatever the user chose is tried before anything easySSH guesses at.
    ///
    /// Both halves live in one test on purpose: the environment belongs to the
    /// whole process, and split in two they would race each other.
    #[cfg(unix)]
    #[test]
    fn the_terminal_env_var_is_tried_first_when_it_is_set() {
        // SAFETY: the variable is set, read back and removed here alone.
        unsafe { std::env::remove_var("TERMINAL") };
        assert_eq!(candidates(None)[0].0, "xdg-terminal-exec");

        unsafe { std::env::set_var("TERMINAL", "/usr/bin/kitty") };
        let chosen = candidates(None)[0].clone();
        // The choice made in easySSH's settings outranks the environment.
        let picked = candidates(Some("konsole"));
        unsafe { std::env::remove_var("TERMINAL") };

        assert_eq!(chosen.0, "/usr/bin/kitty");
        // Recognised by name even when given as a path: kitty takes the
        // command with no flag introducing it, so `-e` would break it.
        assert!(chosen.1.is_empty(), "{:?}", chosen.1);

        assert_eq!(picked[0], ("konsole".to_string(), vec!["-e".to_string()]));
        assert_eq!(picked[1].0, "/usr/bin/kitty");
    }

    /// A chosen terminal is tried once, with its own arguments, and the rest
    /// stay behind it as a fallback.
    #[cfg(unix)]
    #[test]
    fn a_chosen_terminal_leads_and_is_not_tried_twice() {
        let all = candidates(Some("gnome-terminal"));
        assert_eq!(
            all[0],
            ("gnome-terminal".to_string(), vec!["--".to_string()])
        );
        assert_eq!(all.iter().filter(|(b, _)| b == "gnome-terminal").count(), 1);
        assert!(all.iter().any(|(b, _)| b == "xterm"));
    }

    /// Only terminals actually installed are offered, and `sh` stands in for
    /// one: it is on every unix PATH and nowhere else in this test.
    #[cfg(unix)]
    #[test]
    fn on_path_finds_what_is_installed_and_nothing_else() {
        assert!(on_path("sh"));
        assert!(on_path("/bin/sh"));
        assert!(!on_path("easyssh-no-such-terminal"));
    }

    /// What `available` lists is what the setting stores and `open` accepts:
    /// every entry must be one the launcher knows.
    #[test]
    fn available_terminals_have_distinct_ids() {
        let all = available();
        let mut ids: Vec<_> = all.iter().map(|t| t.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), all.len(), "{all:?}");
        #[cfg(target_os = "macos")]
        assert!(all.iter().any(|t| t.id == "terminal"), "{all:?}");
    }

    /// The bug this replaced: a terminal that exits at once having run nothing
    /// was reported as a success, and the candidates after it never tried.
    #[cfg(unix)]
    #[test]
    fn a_terminal_that_fails_immediately_is_not_counted_as_started() {
        let child = std::process::Command::new("sh")
            .args(["-c", "exit 1"])
            .spawn()
            .expect("spawn");
        assert!(!started(child));
    }

    #[cfg(unix)]
    #[test]
    fn a_terminal_that_stays_open_is_counted_as_started() {
        let child = std::process::Command::new("sh")
            .args(["-c", "sleep 5"])
            .spawn()
            .expect("spawn");
        assert!(started(child));
    }

    /// gnome-terminal hands the window to its session daemon and exits at once.
    #[cfg(unix)]
    #[test]
    fn a_terminal_that_hands_off_and_exits_cleanly_is_counted_as_started() {
        let child = std::process::Command::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawn");
        assert!(started(child));
    }

    #[test]
    fn tunnels_are_left_out_entirely_when_not_asked_for() {
        let cmd = ssh_command_line(&profile_with_tunnels(&[4000]), false, &[]);
        assert!(!cmd.contains("-L"), "{cmd}");
        assert!(cmd.ends_with("david@example.com"), "{cmd}");
    }
}
