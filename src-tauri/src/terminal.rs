//! Hand an already-configured `ssh` command to the platform's terminal app.
//!
//! We shell out to the system `ssh` rather than embedding a terminal emulator:
//! it gives you the real thing — your shell, your colours, scrollback, tmux —
//! and it reuses the key easySSH just installed.

use std::process::Command;

use anyhow::Result;

use crate::model::{AuthMethod, Profile};

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
pub fn open(profile: &Profile, include_tunnels: bool, already_forwarded: &[u16]) -> Result<String> {
    let command = ssh_command_line(profile, include_tunnels, already_forwarded);
    launch(&command)?;
    Ok(command)
}

#[cfg(target_os = "macos")]
fn launch(command: &str) -> Result<()> {
    use anyhow::{anyhow, Context as _};

    // Prefer iTerm when the user has it, then fall back to Terminal.app.
    let script = format!(
        r#"
if application "iTerm" is running then
    tell application "iTerm"
        activate
        try
            tell current window to create tab with default profile
        on error
            create window with default profile
        end try
        tell current session of current window to write text {cmd}
    end tell
else
    tell application "Terminal"
        activate
        do script {cmd}
    end tell
end if
"#,
        cmd = applescript_quote(command)
    );

    let status = Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .status()
        .context("running osascript")?;

    if !status.success() {
        // iTerm may exist but be scriptably unhappy; Terminal.app is the safe floor.
        let fallback = format!(
            r#"tell application "Terminal"
    activate
    do script {cmd}
end tell"#,
            cmd = applescript_quote(command)
        );
        let status = Command::new("osascript")
            .arg("-e")
            .arg(&fallback)
            .status()
            .context("running osascript")?;
        if !status.success() {
            return Err(anyhow!("macOS refused to open Terminal"));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn launch(command: &str) -> Result<()> {
    use anyhow::Context as _;
    use std::os::windows::process::CommandExt;

    /// Give the spawned shell its own console. easySSH is a windows-subsystem
    /// binary with no console of its own, so without this the shell would have
    /// nowhere to draw.
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

    // `spawn`, not `status`: the terminal stays open for as long as the user
    // wants it, and waiting on it would block the command that opened it.
    //
    // Windows Terminal gives tabs and a modern renderer. Spawning it directly
    // rather than through `cmd /C start` means a missing wt.exe surfaces as a
    // plain NotFound error instead of a shell quoting puzzle.
    if Command::new("wt.exe")
        .args(["cmd", "/K", command])
        .spawn()
        .is_ok()
    {
        return Ok(());
    }

    Command::new("cmd")
        .args(["/K", command])
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .context("starting cmd.exe")?;

    Ok(())
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn launch(command: &str) -> Result<()> {
    use anyhow::anyhow;

    // `x-terminal-emulator` is Debian's alternatives entry, so on Debian and
    // Ubuntu this lands on whatever terminal the user actually chose; the rest
    // are fallbacks for distributions and desktops that have no such alias.
    const TERMINALS: &[(&str, &[&str])] = &[
        ("x-terminal-emulator", &["-e"]),
        ("gnome-terminal", &["--"]),
        ("konsole", &["-e"]),
        ("kgx", &["--"]),
        ("alacritty", &["-e"]),
        ("kitty", &["--"]),
        ("xterm", &["-e"]),
    ];
    // Drop into a shell when ssh exits instead of closing the window with it:
    // that is what `cmd /K` does on Windows and what Terminal.app does on
    // macOS, and it is the difference between reading why a connection failed
    // and watching the window vanish.
    let script = format!("{command}; exec ${{SHELL:-sh}}");
    for (bin, prefix) in TERMINALS {
        let mut cmd = Command::new(bin);
        cmd.args(*prefix).arg("sh").arg("-c").arg(&script);
        if cmd.spawn().is_ok() {
            return Ok(());
        }
    }
    Err(anyhow!(
        "no terminal emulator found. Install one — on Debian or Ubuntu, \
         `sudo apt-get install gnome-terminal` — or copy the command above."
    ))
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

    #[test]
    fn tunnels_are_left_out_entirely_when_not_asked_for() {
        let cmd = ssh_command_line(&profile_with_tunnels(&[4000]), false, &[]);
        assert!(!cmd.contains("-L"), "{cmd}");
        assert!(cmd.ends_with("david@example.com"), "{cmd}");
    }
}
