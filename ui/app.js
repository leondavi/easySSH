/* easySSH — front end.
   Talks to the Rust side through Tauri's `invoke`; every backend error arrives
   as a plain sentence and is shown verbatim rather than paraphrased. */

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

/* ── tiny DOM helpers ─────────────────────────────────────────────────── */

const $ = (id) => document.getElementById(id);

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "html") el.innerHTML = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}

/** Append children to a node, skipping absent ones. Raw DOM `append(null)`
 *  renders the literal text "null", which is never what a conditional child
 *  is meant to produce. */
function mount(parent, ...children) {
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    parent.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
}

/* ── app state ────────────────────────────────────────────────────────── */

const state = {
  profiles: [],
  keys: [],
  statuses: new Map(),   // profileId -> SessionStatus
  probes: new Map(),     // profileId -> ProbeStatus
  authOpen: false,       // Authentication card expanded by the user
  descriptions: new Map(),
  selectedId: null,
  filter: "",
  connecting: new Set(),
  locations: [],        // every .ssh directory found on this machine
  location: null,       // the one in focus
  configHosts: [],      // Host blocks parsed from the focused config
  showConfigHosts: true, // list hosts read from the ssh config alongside our own
};

const selected = () => state.profiles.find((p) => p.id === state.selectedId) || null;
const statusOf = (id) => state.statuses.get(id) || { connected: false, tunnels: [] };
const probeOf = (id) => state.probes.get(id) || {};

/* ── indicator model ──────────────────────────────────────────────────────
   Four lamps per connection. Each resolves to a colour class plus the words
   shown beside it in the detail pane and in the sidebar tooltip. */

function leds(p) {
  const st = statusOf(p.id);
  const pr = probeOf(p.id);

  // 1. Session — green only while a connection is actually open.
  const connected = st.connected
    ? { cls: "green", label: "Connected", note: "" }
    : { cls: "unknown", label: "Not connected", note: "" };

  // 2. Reachability — blue when the SSH port answers, red when it does not.
  const reachable =
    pr.reachable === true  ? { cls: "blue",    label: "Reachable", note: "" }
  : pr.reachable === false ? { cls: "red",     label: "Unreachable", note: `port ${p.port} did not answer` }
  :                          { cls: "unknown", label: "Reachability unknown", note: "not checked yet" };

  // 3. Key login. An open session already proves it, so trust that over a
  //    stale probe result.
  const provenBySession = st.connected && p.auth === "key";
  const keyAuth =
    p.auth !== "key"        ? { cls: "unknown", label: "Password login", note: "no key configured" }
  : provenBySession         ? { cls: "green",   label: "Key login works", note: "in use now" }
  : pr.key_auth === true    ? { cls: "green",   label: "Key login works", note: "" }
  : pr.key_auth === false   ? { cls: "red",     label: "Key login refused", note: pr.key_auth_note || "" }
  :                           { cls: "unknown", label: "Key login unknown", note: pr.key_auth_note || "not checked yet" };

  // 4. Tunnels — green if any are up, blinking red if one reported an error,
  //    red if they are all down. Absent when the connection defines none.
  let tunnel = null;
  if (p.tunnels.length) {
    const rows = st.tunnels || [];
    const failed = rows.find((t) => t.error);
    const running = rows.filter((t) => t.running).length;
    tunnel = failed
      ? { cls: "red blink", label: "Tunnel error", note: failed.error }
      : running
        ? { cls: "green", label: `${running} of ${p.tunnels.length} tunnel${p.tunnels.length === 1 ? "" : "s"} active`, note: "" }
        : { cls: "red", label: "Tunnels inactive", note: st.connected ? "" : "connect to start them" };
  }

  return { connected, reachable, keyAuth, tunnel };
}

/** Something the user should look at on the Authentication card. */
function authHasIssue(p) {
  const pr = probeOf(p.id);
  if (p.auth === "key" && !p.key_path) return true;
  if (p.auth === "key" && pr.key_auth === false) return true;
  if (p.auth === "key" && !p.key_installed && pr.key_auth !== true) return true;
  return false;
}

/* ── toasts ───────────────────────────────────────────────────────────── */

function toast(message, kind = "", ms = 4200) {
  const el = h("div", { class: `toast ${kind}`.trim(), text: message });
  $("toasts").append(el);
  setTimeout(() => {
    el.style.transition = "opacity 200ms, transform 200ms";
    el.style.opacity = "0";
    el.style.transform = "translateY(6px)";
    setTimeout(() => el.remove(), 220);
  }, ms);
}

const fail = (e) => toast(typeof e === "string" ? e : e?.message ?? String(e), "error", 7000);

/* ── sheets ───────────────────────────────────────────────────────────── */

let closeSheet = null;

function sheet(build) {
  const backdrop = $("sheet-backdrop");
  const host = $("sheet");
  host.replaceChildren();

  const close = () => {
    backdrop.hidden = true;
    host.replaceChildren();
    document.removeEventListener("keydown", onKey);
    closeSheet = null;
  };
  const onKey = (e) => {
    if (e.key === "Escape") { e.preventDefault(); close(); }
  };

  build(host, close);
  backdrop.hidden = false;
  document.addEventListener("keydown", onKey);
  closeSheet = close;

  const first = host.querySelector("input, select, button.btn-primary");
  if (first) setTimeout(() => first.focus(), 30);
  return close;
}

$("sheet-backdrop").addEventListener("mousedown", (e) => {
  if (e.target === $("sheet-backdrop") && closeSheet) closeSheet();
});

/** A labelled row inside a sheet, optionally followed by a hint line.
 *  Returns only the nodes that exist — these get spread into `append()`, and
 *  DOM `append(null)` would render the literal text "null". */
function field(label, control, hint) {
  const rows = [h("div", { class: "sheet-field" }, h("label", { text: label }), control)];
  if (hint) rows.push(h("p", { class: "sheet-hint", text: hint }));
  return rows;
}

/** Run an async action with the button showing a spinner and errors inline. */
function bindSubmit(button, errorBox, action) {
  button.addEventListener("click", async () => {
    errorBox.hidden = true;
    const label = button.textContent;
    button.disabled = true;
    button.replaceChildren(h("span", { class: "spinner" }));
    try {
      await action();
    } catch (e) {
      errorBox.textContent = typeof e === "string" ? e : e?.message ?? String(e);
      errorBox.hidden = false;
    } finally {
      button.disabled = false;
      button.textContent = label;
    }
  });
}

/* ── rendering: sidebar ───────────────────────────────────────────────── */

/** Connections the sidebar should list. Hosts that only exist in the ssh
 *  config can be hidden, leaving easySSH's own — but never one that is
 *  connected or selected, which would make it disappear mid-use. */
function listedProfiles() {
  if (state.showConfigHosts) return state.profiles;
  return state.profiles.filter((p) =>
    !p.from_config || statusOf(p.id).connected || p.id === state.selectedId);
}

function renderSidebar() {
  const list = $("profile-list");
  const term = state.filter.trim().toLowerCase();
  const shown = listedProfiles().filter((p) =>
    !term ||
    p.name.toLowerCase().includes(term) ||
    p.host.toLowerCase().includes(term) ||
    p.username.toLowerCase().includes(term));

  // Live connections float to the top, then most-recently-used.
  shown.sort((a, b) => {
    const live = Number(statusOf(b.id).connected) - Number(statusOf(a.id).connected);
    if (live) return live;
    // Saved connections first, then hosts merely listed in the ssh config.
    // `from_config` is omitted from the wire format when false, so coerce
    // undefined to false rather than letting it become NaN.
    const owned = Number(!!a.from_config) - Number(!!b.from_config);
    if (owned) return owned;
    return (b.last_connected || 0) - (a.last_connected || 0) || a.name.localeCompare(b.name);
  });

  list.replaceChildren(...shown.map((p) => {
    const live = statusOf(p.id).connected;
    const row = h("div", {
      class: `profile-row${p.id === state.selectedId ? " selected" : ""}`,
      onclick: () => select(p.id),
    },
      h("span", { class: `profile-swatch${live ? " live" : ""}`,
                  style: !live && p.color ? `background:${p.color}` : null }),
      h("div", { class: "profile-text" },
        h("span", { class: "profile-name", text: p.name }),
        h("span", { class: "profile-sub", text: `${p.username}@${p.host}` })),
      p.from_config ? h("span", { class: "row-tag", title: "From your ssh config", text: "cfg" }) : null,
      (() => {
        const l = leds(p);
        const shown = [l.connected, l.reachable, l.keyAuth, l.tunnel].filter(Boolean);
        return h("span", {
          class: "row-leds",
          title: shown.map((x) => x.label + (x.note ? ` (${x.note})` : "")).join("\n"),
        }, ...shown.map((x) => h("span", { class: `led ${x.cls}` })));
      })());
    return h("li", {}, row);
  }));

  $("sidebar-empty").hidden = shown.length > 0;
  $("sidebar-empty").textContent = state.filter.trim()
    ? "No matches."
    : state.profiles.length
      ? "No saved connections — the hosts from your ssh config are hidden."
      : "No connections yet.";
}

/* ── rendering: detail ────────────────────────────────────────────────── */

function renderDetail() {
  const p = selected();
  $("empty-state").hidden = !!p;
  $("detail").hidden = !p;
  $("connect-btn").hidden = !p;
  $("terminal-btn").hidden = !p;

  if (!p) {
    $("title").textContent = "easySSH";
    $("subtitle").textContent = "";
    return;
  }

  const st = statusOf(p.id);
  const busy = state.connecting.has(p.id);

  $("title").textContent = p.name;
  $("subtitle").textContent =
    `${p.username}@${p.host}${p.port !== 22 ? `:${p.port}` : ""}`;

  // ── header buttons
  const connectBtn = $("connect-btn");
  connectBtn.textContent = busy ? "Connecting…" : st.connected ? "Disconnect" : "Connect";
  connectBtn.disabled = busy;
  connectBtn.classList.toggle("btn-primary", !st.connected);
  connectBtn.classList.toggle("btn-plain", st.connected);

  // ── status card
  $("status-dot").className = `dot ${busy ? "busy" : st.connected ? "connected" : ""}`;
  $("status-title").textContent = busy
    ? "Connecting…"
    : st.connected ? "Connected" : "Not connected";
  // Only a live session has details worth printing; when disconnected the
  // heading already says everything there is to say.
  $("status-detail").textContent = st.connected
    ? (state.descriptions.get(p.id) || `${p.username}@${p.host}`)
    : "";

  const lamp = leds(p);
  $("led-strip").replaceChildren(
    ...[lamp.connected, lamp.reachable, lamp.keyAuth, lamp.tunnel]
      .filter(Boolean)
      .map((l) => h("div", { class: "led-item", title: l.note || l.label },
        h("span", { class: `led ${l.cls}` }),
        h("span", { class: "led-label", text: l.label }),
        l.note ? h("span", { class: "led-note", text: `· ${l.note}` }) : null)));

  const fpRow = $("fingerprint-row");
  fpRow.hidden = !st.server_fingerprint;
  if (st.server_fingerprint) {
    $("fingerprint").textContent = `Host key ${st.server_fingerprint}` +
      (st.first_contact ? "  ·  newly added to known_hosts" : "");
  }

  // ── auth card
  for (const b of $("auth-seg").children) {
    b.setAttribute("aria-selected", String(b.dataset.auth === p.auth));
  }
  $("key-row").hidden = p.auth !== "key";
  $("key-hint").hidden = p.auth !== "key";

  const badge = $("auth-badge");
  badge.textContent = p.auth === "key" ? "Key" : "Password";
  badge.classList.toggle("ok", p.auth === "key" && p.key_installed);
  if (p.auth === "key" && p.key_installed) badge.textContent = "Key installed";

  // Collapsed by default — the details only matter when you are changing them.
  // An unresolved problem forces it open so the user can see what is wrong
  // without having to know to look here.
  const issue = authHasIssue(p);
  const open = state.authOpen || issue;
  $("auth-toggle").setAttribute("aria-expanded", String(open));
  $("auth-summary").textContent = open
    ? ""
    : p.auth === "key"
      ? [basename(p.key_path || ""), lamp.keyAuth.label].filter(Boolean).join("  ·  ")
      : "Password";

  // For an entry that came from the ssh config, say whether it is set up to log
  // in without a password, and on what basis.
  const configEntry = p.config_alias
    ? state.configHosts.find((x) => x.alias === p.config_alias)
    : null;
  const authLine = $("config-auth");
  authLine.hidden = !configEntry;
  if (configEntry) {
    // auth_note already reads as a full explanation; do not restate it.
    const note = configEntry.auth_note;
    authLine.textContent = configEntry.auto_auth
      ? `Passwordless login ready — ${note}.`
      : `${note.charAt(0).toUpperCase()}${note.slice(1)}.`;
    authLine.classList.toggle("ok", configEntry.auto_auth);
  }

  renderKeyPicker(p);

  const callout = $("setup-callout");
  callout.classList.toggle("done", !!p.key_installed);
  callout.querySelector("strong").textContent = p.key_installed
    ? "Passwordless login is set up"
    : "Set up passwordless login";
  callout.querySelector("p").innerHTML = p.key_installed
    ? `The selected public key is in <span class="mono">~/.ssh/authorized_keys</span> on ${escapeHtml(p.host)}. Run it again to install a different key.`
    : `Sign in with your password once. easySSH appends the selected public key to <span class="mono">~/.ssh/authorized_keys</span> on the server and verifies it works.`;
  $("setup-btn").textContent = p.key_installed ? "Run Again…" : "Set Up…";

  // Is this server already reachable as `ssh <alias>`?
  const inConfig = state.configHosts.find(
    (x) => x.hostname.toLowerCase() === p.host.toLowerCase() && x.port === p.port);
  $("config-state").textContent = inConfig
    ? `In your ssh config as "${inConfig.alias}"`
    : "Not in your ssh config";
  $("config-path").textContent = state.location?.config_path ?? "";
  $("add-config-btn").textContent = inConfig ? "Add Another Alias…" : "Add to Config…";

  // A config host is on loan until it is imported; only then is it ours to
  // give tunnels and a key to.
  $("import-row").hidden = !p.from_config;

  // Entries that only exist in the config cannot be deleted from here.
  $("delete-btn").disabled = !!p.from_config;
  $("delete-btn").title = p.from_config
    ? "This connection comes from your ssh config file"
    : "";

  $("run-input").disabled = !st.connected;
  $("run-btn").disabled = !st.connected;
  $("run-input").placeholder = st.connected
    ? "Run a command on the server…"
    : "Connect to run a command";

  renderTunnels(p, st);
  refreshTerminalPreview(p);
}

/** How a key reads in a picker: `ec2.pem — RSA · PEM (passphrase)`.
 *  The format is named only when it is not the OpenSSH one, so the common
 *  case stays quiet and a `.pem` from AWS is recognisable at a glance.
 *  A key whose permissions the system `ssh` would refuse is marked, because
 *  that failure otherwise only shows up later, in the terminal. */
function keyLabel(k) {
  const detail = [k.algorithm, k.format && k.format !== "OpenSSH" ? k.format : null]
    .filter(Boolean).join(" · ");
  return `${k.name}${detail ? ` — ${detail}` : ""}${k.encrypted ? " (passphrase)" : ""}` +
         `${k.permissions_open ? "  ⚠ permissions too open" : ""}`;
}

/** Tighten a key to 0600 and refresh everything showing it. Used by the two
 *  places that warn about one, so the user never has to reach for chmod. */
async function fixKeyPermissions(path) {
  const key = await invoke("fix_key_permissions", { path });
  await reloadKeys();
  toast(`${key.name} is now 0600 — the terminal will accept it.`, "success");
  return key;
}

/** EC2 instances get names like ec2-13-51-2-3.eu-north-1.compute.amazonaws.com. */
const AWS_HOST = /(^|\.)compute(-\d+)?\.amazonaws\.com$/i;

/** Ask for a key file and let the Rust side work out what it is: either half
 *  of an OpenSSH pair, a .pem straight from the AWS console, or a PuTTY .ppk.
 *  Permissions are fixed and a .pub derived as needed; `note` says what was
 *  done. Returns null if the user cancelled the dialog. */
async function chooseKeyFile() {
  const path = await invoke("pick_key_file", { title: "Choose a private key" });
  if (!path) return null;
  const chosen = await invoke("use_key_file", { path });
  await reloadKeys();
  if (chosen.note) toast(chosen.note, "success", 6000);
  return chosen.key;
}

function renderKeyPicker(p) {
  const sel = $("key-select");
  const options = [...state.keys];

  // A key chosen from outside ~/.ssh still needs to appear in the list.
  if (p.key_path && !options.some((k) => k.path === p.key_path)) {
    options.push({ path: p.key_path, name: basename(p.key_path), algorithm: "", fingerprint: "", encrypted: false, format: "" });
  }

  sel.replaceChildren(
    ...(options.length ? [] : [h("option", { value: "", text: `No keys found in ${state.location?.dir ?? "~/.ssh"}` })]),
    ...options.map((k) => h("option", {
      value: k.path,
      selected: k.path === p.key_path,
      text: k.algorithm ? keyLabel(k) : k.name,
    })));
  sel.value = p.key_path || "";

  const key = options.find((k) => k.path === sel.value);
  const hint = $("key-hint");
  if (key?.permissions_open) {
    // easySSH connects through its own SSH client, which does not care about
    // mode bits; the terminal shells out to the system ssh, which refuses the
    // key outright. Say which one is about to break, and fix it from here.
    hint.replaceChildren(
      h("span", { class: "warn", text:
        `${key.name} is readable by other users. easySSH can still connect, but the ` +
        `terminal's ssh will refuse it.` }),
      " ",
      h("button", { class: "btn btn-plain btn-small", text: "Fix permissions",
        onclick: async () => {
          try { await fixKeyPermissions(key.path); renderDetail(); } catch (e) { fail(e); }
        } }));
    return;
  }
  hint.textContent = key
    ? [key.path, key.fingerprint].filter(Boolean).join("  ·  ")
    : "Choose a key, browse to one, or generate a new pair.";
}

function renderTunnels(p, st) {
  const list = $("tunnel-list");
  $("tunnel-empty").hidden = p.tunnels.length > 0;

  list.replaceChildren(...p.tunnels.map((t) => {
    const ts = (st.tunnels || []).find((x) => x.id === t.id) || { running: false, connections: 0 };
    const canToggle = st.connected;

    const sw = h("div", {
      class: "switch",
      role: "switch",
      "aria-checked": String(!!ts.running),
      "aria-disabled": String(!canToggle),
      title: canToggle ? "" : "Connect first",
      onclick: () => canToggle && toggleTunnel(p, t, !!ts.running),
    });

    return h("li", {}, h("div", { class: "tunnel-row" },
      sw,
      h("div", { class: "tunnel-main" },
        h("span", { class: "tunnel-name", text: t.name || `Port ${t.local_port}` }),
        h("span", { class: "tunnel-path",
          text: `127.0.0.1:${t.local_port} → ${t.remote_host}:${t.remote_port}` +
                (ts.running ? `  ·  ${ts.connections} connection${ts.connections === 1 ? "" : "s"}` : "") }),
        ts.error ? h("span", { class: "tunnel-error", text: ts.error }) : null),
      h("div", { class: "tunnel-actions" },
        h("button", {
          class: "btn btn-plain btn-small",
          disabled: !ts.running,
          onclick: () => invoke("open_url", { url: `${t.scheme}://127.0.0.1:${t.local_port}` }).catch(fail),
          text: "Open",
        }),
        h("button", { class: "btn btn-plain btn-small", text: "Edit",
                      onclick: () => tunnelSheet(p, t) }))));
  }));
}

async function refreshTerminalPreview(p) {
  try {
    const cmd = await invoke("terminal_preview", {
      profileId: p.id,
      includeTunnels: $("term-tunnels").checked,
    });
    $("terminal-preview").textContent = cmd;
  } catch { /* preview only — never block the UI on it */ }
}

/* ── formatting ───────────────────────────────────────────────────────── */

const basename = (p) => p.split(/[\\/]/).pop();
const escapeHtml = (s) => s.replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

/* ── actions ──────────────────────────────────────────────────────────── */

function select(id) {
  if (id !== state.selectedId) {
    state.authOpen = false;
    $("run-output").hidden = true;
    $("run-output").textContent = "";
    $("run-input").value = "";
  }
  state.selectedId = id;
  renderSidebar();
  renderDetail();
  if (id) invoke("remote_description", { profileId: id })
    .then((d) => { if (d) { state.descriptions.set(id, d); renderDetail(); } })
    .catch(() => {});
}

async function reloadProfiles() {
  state.profiles = await invoke("list_profiles");
  if (state.selectedId && !state.profiles.some((p) => p.id === state.selectedId)) {
    state.selectedId = state.profiles[0]?.id ?? null;
  }
  renderSidebar();
  renderDetail();
}

async function reloadKeys() {
  try {
    state.keys = await invoke("list_keys");
  } catch (e) {
    state.keys = [];
    fail(e);
  }
}

/* ── ssh config locations ─────────────────────────────────────────────── */

async function reloadLocations() {
  try {
    state.locations = await invoke("list_ssh_locations");
    state.location = await invoke("active_ssh_location");
  } catch (e) {
    state.locations = [];
    state.location = null;
    fail(e);
  }
  renderLocationPicker();
}

async function reloadSettings() {
  try {
    const s = await invoke("app_settings");
    state.showConfigHosts = s.show_config_hosts !== false;
  } catch { /* keep the current value */ }
  $("show-config-hosts").checked = state.showConfigHosts;
}

async function reloadConfigHosts() {
  try {
    state.configHosts = await invoke("list_ssh_hosts");
  } catch {
    state.configHosts = [];
  }
  renderLocationPicker();
}

function renderLocationPicker() {
  const sel = $("ssh-location");
  const active = state.location?.dir ?? "";

  sel.replaceChildren(...state.locations.map((l) => h("option", {
    value: l.dir,
    selected: l.dir === active,
    // Missing directories stay listed so the user can see what was looked for.
    text: `${l.label}${l.dir_exists ? "" : " — not found"}` +
          (l.dir_exists ? `  ·  ${l.key_count} key${l.key_count === 1 ? "" : "s"}, ${l.host_count} host${l.host_count === 1 ? "" : "s"}` : ""),
  })));
  if (active) sel.value = active;

  // Always say what the current selection produced — including when it
  // produced nothing, so an empty list reads as an answer rather than a
  // failure to update.
  const fromConfig = state.showConfigHosts
    ? state.profiles.filter((p) => p.from_config).length
    : 0;
  const loc = state.location;
  const n = state.configHosts.length;
  const summary = $("location-summary");

  if (!loc) {
    summary.textContent = "";
  } else if (!loc.dir_exists) {
    summary.textContent = "This directory does not exist.";
  } else if (!loc.config_exists) {
    summary.textContent = "No config file in this directory.";
  } else if (n === 0) {
    summary.textContent = "No hosts defined in this config.";
  } else {
    summary.textContent =
      `${n} host${n === 1 ? "" : "s"} in config  ·  ` +
      (state.showConfigHosts
        ? (fromConfig ? `${fromConfig} shown below` : "all already saved")
        : "hidden");
  }
}

async function switchLocation(dir) {
  try {
    state.location = await invoke("set_ssh_location", { dir: dir || null });
    await reloadLocations();      // key and host counts change with the selection
    await reloadKeys();
    await reloadProfiles();       // the config's hosts appear as connections
    await reloadConfigHosts();

    const shown = state.profiles.filter((p) => p.from_config).length;
    toast(shown
      ? `${state.location.dir} — ${shown} connection${shown === 1 ? "" : "s"} from this config`
      : `${state.location.dir} — no connections defined in this config`);
  } catch (e) { fail(e); }
}

async function reloadProbes() {
  try {
    for (const pr of await invoke("probe_statuses")) state.probes.set(pr.profile_id, pr);
    renderSidebar();
    renderDetail();
  } catch { /* probes are advisory; never let them break the UI */ }
}

async function reloadStatuses() {
  try {
    for (const s of await invoke("session_statuses")) state.statuses.set(s.profile_id, s);
    renderSidebar();
    renderDetail();
  } catch { /* transient */ }
}

async function saveProfile(profile) {
  const saved = await invoke("save_profile", { profile });
  await reloadProfiles();
  state.selectedId = saved.id;
  renderSidebar();
  renderDetail();
  return saved;
}

/* connect / disconnect */

async function toggleConnection() {
  const p = selected();
  if (!p) return;

  if (statusOf(p.id).connected) {
    try {
      await invoke("disconnect", { profileId: p.id });
      state.descriptions.delete(p.id);
      toast(`Disconnected from ${p.name}`);
    } catch (e) { fail(e); }
    return;
  }

  // Password auth, and passphrase-protected keys, need a secret from the user.
  const key = state.keys.find((k) => k.path === p.key_path);
  const needsSecret = p.auth === "password" || (p.auth === "key" && key?.encrypted);
  if (needsSecret) {
    secretSheet(p, key?.encrypted && p.auth === "key");
  } else {
    await doConnect(p, null);
  }
}

async function doConnect(p, secret) {
  state.connecting.add(p.id);
  renderDetail();
  try {
    const status = await invoke("connect", { profileId: p.id, secret });
    state.statuses.set(p.id, status);
    const desc = await invoke("remote_description", { profileId: p.id });
    if (desc) state.descriptions.set(p.id, desc);
    await reloadProfiles();
    if (status.first_contact) {
      // Trust-on-first-use: say so plainly rather than trusting silently.
      toast(`Connected to ${p.name}. First time seeing this host — its key ` +
            `${status.server_fingerprint} was added to known_hosts.`, "success", 9000);
    } else {
      toast(`Connected to ${p.name}`, "success");
    }
  } finally {
    state.connecting.delete(p.id);
    renderSidebar();
    renderDetail();
  }
}

function secretSheet(p, isPassphrase) {
  sheet((host, close) => {
    const input = h("input", { type: "password", autocomplete: "off",
                               placeholder: isPassphrase ? "Key passphrase" : "Password" });
    const err = h("div", { class: "sheet-error", hidden: true });
    const go = h("button", { class: "btn btn-primary", text: "Connect" });

    bindSubmit(go, err, async () => {
      await doConnect(p, input.value);
      close();
    });
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") go.click(); });

    mount(host,
      h("h2", { text: isPassphrase ? "Unlock private key" : `Sign in to ${p.name}` }),
      h("p", { class: "sheet-sub",
               text: isPassphrase
                 ? `${basename(p.key_path || "")} is protected by a passphrase.`
                 : `${p.username}@${p.host} — the password is used for this session only and is never saved.` }),
      ...field(isPassphrase ? "Passphrase" : "Password", input),
      err,
      h("div", { class: "sheet-actions" },
        h("button", { class: "btn", text: "Cancel", onclick: close }), go));
  });
}

/* first-run key install */

function setupSheet(p) {
  sheet((host, close) => {
    const pw = h("input", { type: "password", autocomplete: "off", placeholder: "Password" });

    const keySel = h("select", {});
    const rebuildKeys = () => {
      keySel.replaceChildren(...state.keys.map((k) => h("option", {
        value: k.path,
        selected: k.path === p.key_path,
        text: keyLabel(k),
      })));
      if (p.key_path) keySel.value = p.key_path;
    };
    rebuildKeys();

    const genBtn = h("button", { class: "btn btn-small", text: "Generate…",
      onclick: () => generateKeySheet(async (info) => {
        await reloadKeys();
        rebuildKeys();
        keySel.value = info.path;
      }) });

    const err = h("div", { class: "sheet-error", hidden: true });
    const note = h("div", { class: "sheet-note", hidden: true });
    const go = h("button", { class: "btn btn-primary", text: "Install Key" });

    bindSubmit(go, err, async () => {
      if (!keySel.value) throw "Choose or generate a key first.";
      const result = await invoke("setup_key_auth", {
        profileId: p.id,
        password: pw.value,
        keyPath: keySel.value,
      });
      await reloadKeys();
      await reloadProfiles();
      note.textContent = result.already_present
        ? `That key was already in authorized_keys on ${p.host}. Key login verified.`
        : `Key installed on ${p.host} and verified. Future connections will not ask for a password.`;
      note.hidden = false;
      go.hidden = true;
      cancel.textContent = "Done";
      toast("Passwordless login is set up", "success");
    });
    pw.addEventListener("keydown", (e) => { if (e.key === "Enter") go.click(); });

    const cancel = h("button", { class: "btn", text: "Cancel", onclick: close });

    mount(host,
      h("h2", { text: "Set up passwordless login" }),
      h("p", { class: "sheet-sub",
               text: `easySSH signs in to ${p.username}@${p.host} with your password, appends the public key to the server's authorized_keys, then proves the key works by logging in again with it.` }),
      ...field("Password", pw, "Used once, for this setup only. Never written to disk."),
      ...field("Key", h("div", { class: "grow", style: "display:flex;gap:6px" }, keySel, genBtn)),
      note, err,
      h("div", { class: "sheet-actions" }, cancel, go));
  });
}

/* public key viewer */

async function showPublicKeySheet(path) {
  let text;
  try {
    text = await invoke("public_key_text", { path });
  } catch (e) { fail(e); return; }

  sheet((host, close) => {
    const box = h("textarea", { class: "key-text", readonly: true, spellcheck: "false" });
    box.value = text;

    const copy = h("button", { class: "btn btn-primary", text: "Copy" , onclick: async () => {
      try {
        await navigator.clipboard.writeText(text);
        copy.textContent = "Copied";
        setTimeout(() => { copy.textContent = "Copy"; }, 1400);
      } catch {
        // Clipboard can be refused; selecting the text is always available.
        box.select();
        toast("Press ⌘C / Ctrl+C to copy the selected text");
      }
    }});

    mount(host,
      h("h2", { text: "Public key" }),
      h("p", { class: "sheet-sub",
               text: `${basename(path)} — paste this line into ~/.ssh/authorized_keys on any server to allow passwordless login.` }),
      box,
      h("div", { class: "sheet-actions" },
        h("button", { class: "btn", text: "Close", onclick: close }), copy));

    setTimeout(() => box.select(), 40);
  });
}

/* key generation */

function generateKeySheet(onCreated) {
  sheet((host, close) => {
    const name = h("input", { type: "text", value: suggestKeyName(), spellcheck: "false" });
    const algo = h("select", {},
      h("option", { value: "ed25519", text: "Ed25519 — recommended" }),
      h("option", { value: "rsa", text: "RSA 4096 — maximum compatibility" }));
    const comment = h("input", { type: "text", value: `easySSH@${location.hostname || "local"}`, spellcheck: "false" });
    const pass = h("input", { type: "password", autocomplete: "new-password", placeholder: "Optional" });

    const err = h("div", { class: "sheet-error", hidden: true });
    const go = h("button", { class: "btn btn-primary", text: "Generate" });

    bindSubmit(go, err, async () => {
      const info = await invoke("generate_key", {
        name: name.value.trim(),
        algorithm: algo.value,
        comment: comment.value,
        passphrase: pass.value || null,
      });
      await reloadKeys();
      toast(`Created ${info.name}`, "success");
      close();
      onCreated?.(info);
    });

    mount(host,
      h("h2", { text: "Generate a new key pair" }),
      h("p", { class: "sheet-sub",
               text: `Written to ${state.location?.dir ?? "~/.ssh"} with the private key set to owner-only permissions.` }),
      ...field("File name", name, "The public half is saved alongside it as <name>.pub."),
      ...field("Type", algo),
      ...field("Comment", comment),
      ...field("Passphrase", pass, "A passphrase means easySSH asks to unlock the key on each connection."),
      err,
      h("div", { class: "sheet-actions" },
        h("button", { class: "btn", text: "Cancel", onclick: close }), go));
  });
}

function suggestKeyName() {
  const base = "id_easyssh_ed25519";
  if (!state.keys.some((k) => k.name === base)) return base;
  for (let i = 2; i < 100; i++) {
    const n = `${base}_${i}`;
    if (!state.keys.some((k) => k.name === n)) return n;
  }
  return base;
}

async function browseForKey() {
  const p = selected();
  if (!p) return;
  try {
    // Whatever they picked is resolved and made usable before it is saved, so
    // a wrong pick fails here rather than at connect time.
    const info = await chooseKeyFile();
    if (!info) return;
    if (!state.keys.some((k) => k.path === info.path)) state.keys.push(info);
    await saveProfile({ ...p, key_path: info.path, auth: "key" });
    toast(`Using ${info.name}`);
  } catch (e) { fail(e); }
}

/* tunnels */

/** Make a just-saved tunnel match the live session: restart it if it was
 *  already forwarding, or start it if it is meant to come up on its own. */
async function applyTunnelToLiveSession(profileId, t, wasRunning) {
  if (!statusOf(profileId).connected) return;
  if (!wasRunning && !t.auto_start) return;
  try {
    if (wasRunning) {
      await invoke("stop_tunnel", { profileId, tunnelId: t.id });
    }
    await invoke("start_tunnel", { profileId, tunnelId: t.id });
  } catch (e) { fail(e); }
  await reloadStatuses();
}

async function toggleTunnel(p, t, running) {
  try {
    await invoke(running ? "stop_tunnel" : "start_tunnel", { profileId: p.id, tunnelId: t.id });
  } catch (e) { fail(e); }
  await reloadStatuses();
}

/** Take a host that only exists in the ssh config and make it easySSH's own,
 *  written to ez_config from here on. */
async function importHost(p) {
  try {
    const saved = await invoke("import_ssh_host", { profileId: p.id });
    await reloadProfiles();
    await reloadConfigHosts();
    select(saved.id);
    toast(`${saved.name} imported — it is now saved in easySSH`);
  } catch (e) { fail(e); }
}

function tunnelSheet(p, existing) {
  sheet((host, close) => {
    const t = existing || {
      id: "", name: "", local_port: suggestLocalPort(p), remote_host: "localhost",
      remote_port: 8080, auto_start: true, scheme: "http",
    };

    const name = h("input", { type: "text", value: t.name, placeholder: "Web UI", spellcheck: "false" });
    const localPort = h("input", { type: "number", min: "1", max: "65535", value: String(t.local_port) });
    const remoteHost = h("input", { type: "text", value: t.remote_host, spellcheck: "false" });
    const remotePort = h("input", { type: "number", min: "1", max: "65535", value: String(t.remote_port) });
    const scheme = h("select", {},
      h("option", { value: "http", text: "http", selected: t.scheme !== "https" }),
      h("option", { value: "https", text: "https", selected: t.scheme === "https" }));
    const auto = h("input", { type: "checkbox", checked: !!t.auto_start });

    const err = h("div", { class: "sheet-error", hidden: true });
    const go = h("button", { class: "btn btn-primary", text: existing ? "Save" : "Add Tunnel" });

    bindSubmit(go, err, async () => {
      const lp = Number(localPort.value), rp = Number(remotePort.value);
      if (!(lp >= 1 && lp <= 65535)) throw "The local port must be between 1 and 65535.";
      if (!(rp >= 1 && rp <= 65535)) throw "The remote port must be between 1 and 65535.";
      if (!remoteHost.value.trim()) throw "Enter the address as the server sees it.";

      const next = {
        id: t.id || crypto.randomUUID(),
        name: name.value.trim() || `Port ${lp}`,
        local_port: lp,
        remote_host: remoteHost.value.trim(),
        remote_port: rp,
        auto_start: auto.checked,
        scheme: scheme.value,
      };
      const tunnels = existing
        ? p.tunnels.map((x) => (x.id === t.id ? next : x))
        : [...p.tunnels, next];
      const wasRunning = !!(statusOf(p.id).tunnels || []).find((x) => x.id === next.id)?.running;
      await saveProfile({ ...p, tunnels });
      close();
      // A tunnel is only auto-started when the connection opens, so one added
      // or edited on a session that is already up would otherwise sit idle
      // until the next reconnect. Bring it up here instead, and restart a
      // running one so the edited ports are the ones actually forwarded.
      await applyTunnelToLiveSession(p.id, next, wasRunning);
    });

    const remove = existing ? h("button", {
      class: "btn btn-danger", text: "Remove",
      onclick: async () => {
        try {
          if (statusOf(p.id).connected) {
            await invoke("stop_tunnel", { profileId: p.id, tunnelId: t.id }).catch(() => {});
          }
          await saveProfile({ ...p, tunnels: p.tunnels.filter((x) => x.id !== t.id) });
          close();
        } catch (e) { fail(e); }
      },
    }) : null;

    mount(host,
      h("h2", { text: existing ? "Edit tunnel" : "Add a web tunnel" }),
      h("p", { class: "sheet-sub",
               text: "The remote address is resolved on the server, so 'localhost' means the server itself and any other name resolves on its network." }),
      ...field("Name", name),
      ...field("Local port", localPort, "Opened on 127.0.0.1 on this machine."),
      ...field("Remote host", remoteHost, "As seen from the server: localhost, an internal IP, or a hostname on its LAN."),
      ...field("Remote port", remotePort),
      ...field("Scheme", scheme, "Used for the Open button's URL."),
      h("div", { class: "sheet-field" },
        h("label", {}),
        h("label", { class: "checkbox", style: "margin:0" }, auto,
          h("span", { text: "Start automatically when this connection opens" }))),
      err,
      h("div", { class: "sheet-actions" },
        remove,
        h("button", { class: "btn", text: "Cancel", onclick: close }), go));
  });
}

function suggestLocalPort(p) {
  const used = new Set(p.tunnels.map((t) => t.local_port));
  for (let port = 8080; port < 8180; port++) if (!used.has(port)) return port;
  return 8080;
}

/* write a connection into the ssh config */

function addToConfigSheet(p) {
  sheet((host, close) => {
    const alias = h("input", { type: "text", value: suggestAlias(p), spellcheck: "false" });
    const withTunnels = h("input", { type: "checkbox", checked: p.tunnels.length > 0,
                                     disabled: p.tunnels.length === 0 });

    const err = h("div", { class: "sheet-error", hidden: true });
    const note = h("div", { class: "sheet-note", hidden: true });
    const go = h("button", { class: "btn btn-primary", text: "Add to Config" });

    bindSubmit(go, err, async () => {
      const block = await invoke("add_to_ssh_config", {
        profileId: p.id,
        alias: alias.value.trim(),
        includeTunnels: withTunnels.checked,
      });
      await reloadConfigHosts();
      renderDetail();
      note.textContent = block;
      note.hidden = false;
      go.hidden = true;
      cancel.textContent = "Done";
      toast(`ssh ${alias.value.trim()} will now connect straight to ${p.host}`, "success", 6000);
    });

    const cancel = h("button", { class: "btn", text: "Cancel", onclick: close });

    mount(host,
      h("h2", { text: "Add to ssh config" }),
      h("p", { class: "sheet-sub",
               text: `Appends a Host block to ${state.location?.config_path ?? "your ssh config"}. Existing blocks are never rewritten.` }),
      ...field("Alias", alias, "What you will type: ssh <alias>"),
      h("div", { class: "sheet-field" },
        h("label", {}),
        h("label", { class: "checkbox", style: "margin:0" }, withTunnels,
          h("span", { text: p.tunnels.length
            ? `Include ${p.tunnels.length} tunnel${p.tunnels.length === 1 ? "" : "s"} as LocalForward lines`
            : "No tunnels to include" }))),
      note, err,
      h("div", { class: "sheet-actions" }, cancel, go));
  });
}

function suggestAlias(p) {
  const base = (p.name || p.host).toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  const taken = new Set(state.configHosts.map((x) => x.alias.toLowerCase()));
  if (base && !taken.has(base)) return base;
  for (let i = 2; i < 100; i++) if (!taken.has(`${base}-${i}`)) return `${base}-${i}`;
  return base || p.host;
}

/* profile editor */

function profileSheet(existing) {
  sheet((host, close) => {
    const p = existing || {
      id: "", name: "", host: "", port: 22, username: "", auth: "password",
      key_path: state.keys[0]?.path ?? null, tunnels: [], last_connected: null,
      color: null, key_installed: false,
    };

    const name = h("input", { type: "text", value: p.name, placeholder: "Production web", spellcheck: "false" });
    const hostIn = h("input", { type: "text", value: p.host, placeholder: "example.com or 10.0.0.5", spellcheck: "false" });
    const port = h("input", { type: "number", min: "1", max: "65535", value: String(p.port) });
    const user = h("input", { type: "text", value: p.username, placeholder: "ubuntu", spellcheck: "false" });

    const authSel = h("select", {},
      h("option", { value: "password", text: "Password", selected: p.auth === "password" }),
      h("option", { value: "key", text: "Private key", selected: p.auth === "key" }));

    const keySel = h("select", {}, ...state.keys.map((k) => h("option", {
      value: k.path, selected: k.path === p.key_path, text: keyLabel(k),
    })));
    if (!state.keys.length) keySel.append(h("option", { value: "", text: "No keys found" }));

    const useKey = (info) => {
      if (![...keySel.options].some((o) => o.value === info.path)) {
        keySel.append(h("option", { value: info.path, text: keyLabel(info) }));
      }
      keySel.value = info.path;
      syncKeyWarn();
    };

    // A key already in ~/.ssh can be one the system ssh will not touch — moved
    // in by hand, restored from a backup. Warn before the connection is made
    // rather than after, when the error would come from ssh instead of us.
    const keyWarn = h("p", { class: "sheet-hint", hidden: true });
    const syncKeyWarn = () => {
      const k = state.keys.find((x) => x.path === keySel.value);
      keyWarn.hidden = !k?.permissions_open;
      if (keyWarn.hidden) return;
      keyWarn.replaceChildren(
        h("span", { class: "warn", text:
          `${k.name} is readable by other users, and the terminal's ssh refuses such a key.` }),
        " ",
        h("button", { class: "btn btn-plain btn-small", text: "Fix permissions",
          onclick: async () => {
            try {
              const fixed = await fixKeyPermissions(k.path);
              useKey(fixed);
              syncKeyWarn();
            } catch (e) { fail(e); }
          } }));
    };
    keySel.addEventListener("change", syncKeyWarn);

    const keyRow = h("div", { class: "sheet-field" },
      h("label", { text: "Key" }),
      h("div", { class: "grow", style: "display:flex;flex-wrap:wrap;gap:6px" },
        keySel,
        h("button", { class: "btn btn-small", text: "Browse…",
          onclick: async () => {
            try {
              const info = await chooseKeyFile();
              if (info) useKey(info);
            } catch (e) { fail(e); }
          } }),
        h("button", { class: "btn btn-small", text: "Generate…",
          onclick: () => generateKeySheet(async (info) => {
            await reloadKeys();
            useKey(info);
          }) })));

    const syncAuth = () => {
      keyRow.hidden = authSel.value !== "key";
      if (keyRow.hidden) keyWarn.hidden = true;
      else syncKeyWarn();
    };

    // An EC2 instance has no password login at all: the key pair chosen when
    // it was launched is the only way in, and its user name comes from the AMI
    // rather than from anything we can see. So say so, and start them on the
    // key — but never overrule a choice they have already made.
    let authTouched = false;
    const awsHint = h("p", { class: "sheet-hint", hidden: true, text:
      "AWS EC2. The user name depends on the image: ec2-user (Amazon Linux), " +
      "ubuntu (Ubuntu), admin (Debian), or centos / rocky / fedora / bitnami. " +
      "Sign in with the .pem from the key pair you picked when launching the " +
      "instance: Browse… to it and easySSH sorts out its permissions." });
    const syncAws = () => {
      const isAws = AWS_HOST.test(hostIn.value.trim());
      awsHint.hidden = !isAws;
      if (!isAws) return;
      if (!user.value.trim()) user.value = "ec2-user";
      if (!existing && !authTouched && authSel.value !== "key") {
        authSel.value = "key";
        syncAuth();
      }
    };
    hostIn.addEventListener("input", syncAws);
    authSel.addEventListener("change", () => { authTouched = true; syncAuth(); });
    syncAuth();
    syncAws();

    const err = h("div", { class: "sheet-error", hidden: true });
    const go = h("button", { class: "btn btn-primary", text: existing ? "Save" : "Add" });

    bindSubmit(go, err, async () => {
      const portNum = Number(port.value);
      if (!(portNum >= 1 && portNum <= 65535)) throw "The port must be between 1 and 65535.";
      await saveProfile({
        ...p,
        name: name.value.trim() || hostIn.value.trim(),
        host: hostIn.value.trim(),
        port: portNum,
        username: user.value.trim(),
        auth: authSel.value,
        key_path: authSel.value === "key" ? (keySel.value || null) : p.key_path,
      });
      close();
    });

    mount(host,
      h("h2", { text: existing ? "Edit connection" : "New connection" }),
      h("p", { class: "sheet-sub",
               text: "Start with your password — you can install a key for passwordless login right after connecting." }),
      ...field("Name", name),
      ...field("Host", hostIn),
      ...field("Port", port),
      ...field("User", user),
      awsHint,
      ...field("Sign in with", authSel),
      keyRow,
      keyWarn,
      err,
      h("div", { class: "sheet-actions" },
        h("button", { class: "btn", text: "Cancel", onclick: close }), go));
  });
}

function confirmDelete(p) {
  sheet((host, close) => {
    const err = h("div", { class: "sheet-error", hidden: true });
    const go = h("button", { class: "btn btn-danger", text: "Delete" });
    bindSubmit(go, err, async () => {
      await invoke("delete_profile", { profileId: p.id });
      state.statuses.delete(p.id);
      state.selectedId = null;
      await reloadProfiles();
      close();
      toast(`Deleted ${p.name}`);
    });
    mount(host,
      h("h2", { text: `Delete "${p.name}"?` }),
      h("p", { class: "sheet-sub",
               text: "This removes the connection and its tunnels from easySSH. The server, and any key already installed on it, are left untouched." }),
      err,
      h("div", { class: "sheet-actions" },
        h("button", { class: "btn", text: "Cancel", onclick: close }), go));
  });
}

/* known hosts editor */

async function knownHostsSheet() {
  let entries, filePath;
  try {
    [entries, filePath] = await Promise.all([
      invoke("list_known_hosts"),
      invoke("known_hosts_path"),
    ]);
  } catch (e) { fail(e); return; }

  sheet((host, close) => {
    host.classList.add("sheet-wide");
    const selection = new Map();   // line -> fingerprint
    let filter = "";

    const listEl = h("div", { class: "host-list" });
    const countEl = h("span", {});
    const removeBtn = h("button", { class: "btn btn-danger", text: "Remove" });
    const err = h("div", { class: "sheet-error", hidden: true });

    const describe = (e) => {
      if (e.hashed) return "hashed entry — name not recoverable";
      if (!e.hosts.length) return "unreadable line";
      return e.hosts.join(", ");
    };

    const matches = (e) => {
      if (!filter) return true;
      const hay = [...e.hosts, e.fingerprint, e.comment, e.algorithm].join(" ").toLowerCase();
      return hay.includes(filter);
    };

    function paint() {
      const visible = entries.filter(matches);

      listEl.replaceChildren(...(visible.length ? visible.map((e) => {
        const cb = h("input", {
          type: "checkbox",
          checked: selection.has(e.line),
          onchange: (ev) => {
            if (ev.target.checked) selection.set(e.line, e.fingerprint);
            else selection.delete(e.line);
            paint();
          },
        });

        return h("div", { class: `host-entry${selection.has(e.line) ? " selected-for-removal" : ""}` },
          cb,
          h("div", { class: "entry-main" },
            h("span", {
              class: `entry-host${e.hosts.length ? "" : " unnamed"}`,
              text: describe(e),
            }),
            h("span", { class: "entry-meta",
                        text: [e.algorithm, e.fingerprint].filter(Boolean).join("  ·  ") || `line ${e.line}` }),
            e.comment ? h("span", { class: "entry-meta", text: e.comment }) : null,
            e.used_by.length
              ? h("span", { class: "entry-used", text: `Used by ${e.used_by.join(", ")}` })
              : null),
          h("div", { class: "entry-tags" },
            e.marker ? h("span", { class: "tag danger", text: e.marker }) : null,
            e.hashed ? h("span", { class: "tag", text: "hashed" }) : null,
            !e.parsed ? h("span", { class: "tag warn", text: "unreadable" }) : null,
            h("span", { class: "tag", text: `line ${e.line}` })));
      }) : [h("p", { class: "muted-row", text: filter ? "No matches." : "This file has no entries." })]));

      const n = selection.size;
      countEl.textContent =
        `${entries.length} entr${entries.length === 1 ? "y" : "ies"}` +
        (filter ? `  ·  ${visible.length} shown` : "") +
        (n ? `  ·  ${n} selected` : "");
      removeBtn.disabled = n === 0;
      removeBtn.textContent = n ? `Remove ${n}` : "Remove";
    }

    const search = h("input", {
      type: "text", placeholder: "Filter by host, fingerprint or comment", spellcheck: "false",
      oninput: (ev) => { filter = ev.target.value.trim().toLowerCase(); paint(); },
    });

    bindSubmit(removeBtn, err, async () => {
      const chosen = [...selection.entries()].map(([line, fingerprint]) => ({ line, fingerprint }));
      const removed = await invoke("remove_known_hosts", { entries: chosen });

      // Re-read rather than patching locally: line numbers shift on every
      // delete, and a stale list would target the wrong rows next time.
      entries = await invoke("list_known_hosts");
      selection.clear();
      paint();
      toast(`Removed ${removed} entr${removed === 1 ? "y" : "ies"} from known_hosts`, "success");
    });

    mount(host,
      h("h2", { text: "Known hosts" }),
      h("p", { class: "sheet-sub", text: `${filePath} — the host keys easySSH and ssh trust. Remove an entry when a server has been rebuilt or its key legitimately changed; the next connection records the new one.` }),
      h("div", { class: "select-all-row" },
        countEl,
        h("div", {},
          h("button", { class: "link-btn", text: "Select all shown",
            onclick: () => {
              for (const e of entries.filter(matches)) selection.set(e.line, e.fingerprint);
              paint();
            } }),
          h("span", { text: "  ·  " }),
          h("button", { class: "link-btn", text: "None",
            onclick: () => { selection.clear(); paint(); } }))),
      search,
      listEl,
      err,
      h("div", { class: "sheet-actions" },
        h("button", { class: "btn", text: "Close",
          onclick: () => { host.classList.remove("sheet-wide"); close(); } }),
        removeBtn));

    search.style.width = "100%";
    search.style.marginBottom = "6px";
    paint();
  });
}

/* keys overview */

function keysSheet() {
  sheet((host, close) => {
    const rows = state.keys.length
      ? state.keys.map((k) => h("div", { class: "tunnel-row" },
          h("div", { class: "tunnel-main" },
            h("span", { class: "tunnel-name", text: `${k.name}  ·  ${k.algorithm}${k.encrypted ? "  ·  passphrase" : ""}` }),
            h("span", { class: "tunnel-path mono", text: k.fingerprint }),
            k.comment ? h("span", { class: "tunnel-path", text: k.comment }) : null),
          h("button", {
            class: "btn btn-plain btn-small", text: "Show",
            onclick: () => showPublicKeySheet(k.path),
          }),
          h("button", {
            class: "btn btn-plain btn-small", text: "Copy",
            onclick: async () => {
              try {
                const text = await invoke("public_key_text", { path: k.path });
                await navigator.clipboard.writeText(text);
                toast("Public key copied");
              } catch (e) { fail(e); }
            },
          })))
      : [h("p", { class: "muted-row",
                  text: `No keys found in ${state.location?.dir ?? "~/.ssh"} yet.` })];

    mount(host,
      h("h2", { text: "SSH keys" }),
      h("p", { class: "sheet-sub",
               text: `Private keys found in ${state.location?.dir ?? "~/.ssh"}.` }),
      h("div", {}, ...rows),
      h("div", { class: "sheet-actions" },
        h("button", { class: "btn", text: "Close", onclick: close }),
        h("button", { class: "btn btn-primary", text: "Generate…",
                      onclick: () => generateKeySheet(() => keysSheet()) })));
  });
}

/* ── wiring ───────────────────────────────────────────────────────────── */

$("search").addEventListener("input", (e) => { state.filter = e.target.value; renderSidebar(); });
$("new-profile").addEventListener("click", () => profileSheet(null));
$("empty-new").addEventListener("click", () => profileSheet(null));
$("manage-keys").addEventListener("click", keysSheet);
$("manage-hosts").addEventListener("click", knownHostsSheet);
$("connect-btn").addEventListener("click", toggleConnection);
$("edit-btn").addEventListener("click", () => selected() && profileSheet(selected()));

/* Quick command runner — handy for checking what is listening before
   pointing a tunnel at it. */
async function runQuickCommand() {
  const p = selected();
  const command = $("run-input").value.trim();
  if (!p || !command) return;

  const out = $("run-output");
  const btn = $("run-btn");
  btn.disabled = true;
  out.hidden = false;
  out.className = "run-output mono";
  out.textContent = "Running…";

  try {
    const r = await invoke("run_command", { profileId: p.id, command });
    const parts = [];
    if (r.stdout.trim()) parts.push(r.stdout.replace(/\s+$/, ""));
    if (r.stderr.trim()) parts.push(r.stderr.replace(/\s+$/, ""));

    if (parts.length) {
      // A non-zero status matters even when there is output to show.
      if (r.code !== 0) parts.push(`\n[exit status ${r.code}]`);
      out.textContent = parts.join("\n");
    } else {
      // Never leave the user staring at a blank box: the exit status is the
      // only clue about why a command printed nothing.
      out.textContent = r.code === 0
        ? "The command ran and exited 0 without printing anything."
        : `The command printed nothing and exited with status ${r.code}.` +
          (r.code === 127 ? " Status 127 usually means the command was not found." : "");
    }
    out.classList.toggle("failed", r.code !== 0);
  } catch (e) {
    out.textContent = typeof e === "string" ? e : String(e);
    out.classList.add("failed");
  } finally {
    btn.disabled = false;
  }
}

$("run-btn").addEventListener("click", runQuickCommand);
$("run-input").addEventListener("keydown", (e) => { if (e.key === "Enter") runQuickCommand(); });
$("delete-btn").addEventListener("click", () => selected() && confirmDelete(selected()));
$("import-btn").addEventListener("click", () => selected() && importHost(selected()));
$("show-config-hosts").addEventListener("change", async (e) => {
  const show = e.target.checked;
  try {
    await invoke("set_show_config_hosts", { show });
    state.showConfigHosts = show;
  } catch (err) {
    e.target.checked = state.showConfigHosts;   // the setting did not stick
    fail(err);
  }
  renderSidebar();
  renderLocationPicker();
});
$("setup-btn").addEventListener("click", () => selected() && setupSheet(selected()));
$("add-tunnel").addEventListener("click", () => selected() && tunnelSheet(selected(), null));
$("auth-toggle").addEventListener("click", () => {
  // A forced-open card can still be collapsed; the next render re-opens it
  // while the problem remains, which is the behaviour we want.
  state.authOpen = $("auth-toggle").getAttribute("aria-expanded") !== "true";
  renderDetail();
});

$("browse-key").addEventListener("click", browseForKey);
$("show-key").addEventListener("click", () => {
  const p = selected();
  if (!p?.key_path) { toast("Choose a key first"); return; }
  showPublicKeySheet(p.key_path);
});
$("add-config-btn").addEventListener("click", () => selected() && addToConfigSheet(selected()));
$("ssh-location").addEventListener("change", (e) => switchLocation(e.target.value));
$("generate-key").addEventListener("click", () => generateKeySheet(async (info) => {
  const p = selected();
  if (p) await saveProfile({ ...p, auth: "key", key_path: info.path });
}));

$("key-select").addEventListener("change", async (e) => {
  const p = selected();
  if (!p || !e.target.value) return;
  try { await saveProfile({ ...p, key_path: e.target.value }); } catch (err) { fail(err); }
});

$("auth-seg").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-auth]");
  const p = selected();
  if (!btn || !p || btn.dataset.auth === p.auth) return;
  if (btn.dataset.auth === "key" && !p.key_path && !state.keys.length) {
    generateKeySheet(async (info) => { await saveProfile({ ...p, auth: "key", key_path: info.path }); });
    return;
  }
  try {
    await saveProfile({ ...p, auth: btn.dataset.auth, key_path: p.key_path || state.keys[0]?.path || null });
  } catch (err) { fail(err); }
});

$("terminal-btn").addEventListener("click", async () => {
  const p = selected();
  if (!p) return;
  try {
    await invoke("open_terminal", { profileId: p.id, includeTunnels: $("term-tunnels").checked });
  } catch (e) { fail(e); }
});

$("term-tunnels").addEventListener("change", () => {
  const p = selected();
  if (p) refreshTerminalPreview(p);
});

/* backend push */

listen("session-status", (e) => {
  state.statuses.set(e.payload.profile_id, e.payload);
  renderSidebar();
  renderDetail();
});

listen("probe-status", (e) => {
  for (const pr of e.payload) state.probes.set(pr.profile_id, pr);
  renderSidebar();
  renderDetail();
});

listen("tunnel-error", (e) => fail(e.payload.error));

/* easySSH tightened — or could not tighten — a key on the way to using it.
   Said out loud because it is a change to a file the user owns. */
listen("key-notice", async (e) => {
  await reloadKeys();
  renderDetail();
  toast(e.payload.message, e.payload.fixed ? "success" : "error", 9000);
});
listen("keys-changed", () => reloadKeys());
listen("profiles-changed", () => reloadProfiles());
listen("ssh-location-changed", async () => { await reloadConfigHosts(); renderDetail(); });

/* The ssh config was edited outside easySSH; the backend has already re-read
   it, so refresh what the sidebar and detail pane are showing. */
listen("ssh-config-changed", async () => {
  const before = state.profiles.filter((p) => p.from_config).length;
  await reloadProfiles();
  await reloadConfigHosts();
  await reloadLocations();
  renderDetail();

  const after = state.profiles.filter((p) => p.from_config).length;
  const delta = after - before;
  toast(delta === 0
    ? "ssh config changed — connections refreshed"
    : delta > 0
      ? `ssh config changed — ${delta} connection${delta === 1 ? "" : "s"} added`
      : `ssh config changed — ${-delta} connection${delta === -1 ? "" : "s"} removed`);
});

/* Keep connection counters fresh while a session is open. */
setInterval(() => {
  if ([...state.statuses.values()].some((s) => s.connected)) reloadStatuses();
}, 2500);

/* ── boot ─────────────────────────────────────────────────────────────── */

(async function boot() {
  await reloadSettings();
  await reloadLocations();
  await reloadKeys();
  await reloadProfiles();
  await reloadConfigHosts();
  await reloadStatuses();
  await reloadProbes();
  if (!state.selectedId && state.profiles.length) select(state.profiles[0].id);
  renderDetail();
})().catch(fail);
