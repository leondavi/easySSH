#!/usr/bin/env bash
# Build easySSH installers.
#
#   ./scripts/build.sh              # bundle for the machine you are on
#   ./scripts/build.sh macos        # .dmg + .app       (must run on macOS)
#   ./scripts/build.sh windows      # .exe + .msi       (must run on Windows, or see below)
#   ./scripts/build.sh linux        # .deb              (must run on Debian or Ubuntu)
#   ./scripts/build.sh all          # everything this machine can produce
#   ./scripts/build.sh --universal  # macOS: one binary for Apple Silicon + Intel
#
# Cross-compiling Windows installers from macOS is not supported by the Tauri
# bundler (NSIS and WiX need Windows). Use scripts/build.ps1 on a Windows box,
# or the GitHub Actions workflow in .github/workflows/release.yml, which builds
# both from one tag.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; OFF=$'\033[0m'
say()  { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
warn() { printf '%s warn%s %s\n' "$YELLOW" "$OFF" "$*"; }
die()  { printf '%serror%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

TARGET="${1:-auto}"
UNIVERSAL=0
for arg in "$@"; do
  [[ "$arg" == "--universal" ]] && UNIVERSAL=1
done
[[ "$TARGET" == "--universal" ]] && TARGET="auto"

# ── prerequisites ────────────────────────────────────────────────────────────

command -v cargo >/dev/null || die "Rust is not installed. See https://rustup.rs"

if ! cargo tauri --version >/dev/null 2>&1; then
  say "Installing the Tauri CLI (one time)"
  cargo install tauri-cli --version "^2" --locked
fi

case "$(uname -s)" in
  Darwin) HOST=macos ;;
  MINGW*|MSYS*|CYGWIN*) HOST=windows ;;
  *) HOST=linux ;;
esac
[[ "$TARGET" == "auto" || "$TARGET" == "all" ]] && TARGET="$HOST"

say "Host: $HOST   Building: $TARGET"

# ── build ────────────────────────────────────────────────────────────────────

BUNDLE_DIR="src-tauri/target/release/bundle"

build_macos() {
  [[ "$HOST" == "macos" ]] || die "macOS bundles must be built on macOS."

  local args=(--bundles dmg,app)
  if [[ "$UNIVERSAL" == "1" ]]; then
    say "Adding Rust targets for a universal binary"
    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    args+=(--target universal-apple-darwin)
    BUNDLE_DIR="src-tauri/target/universal-apple-darwin/release/bundle"
  fi

  # An interrupted bundle_dmg.sh leaves a read-write scratch image behind, and
  # often still mounted. The next run then fails outright, because the image is
  # busy, so detach anything backed by one of ours before clearing them.
  # `hdiutil info` prints the device on a line of its own, but with the
  # partition scheme tabbed after it — matching the whole line finds nothing,
  # which is how these leftovers used to survive and break the next build.
  hdiutil info 2>/dev/null | awk -v proj="$ROOT" '
    /^image-path/ { img=$0; sub(/^image-path[ \t]*:[ \t]*/, "", img) }
    $1 ~ /^\/dev\/disk[0-9]+$/ { if (index(img, proj) && index(img, "rw.")) print $1 }
  ' | while read -r dev; do
    warn "detaching leftover disk image $dev"
    hdiutil detach "$dev" -force >/dev/null 2>&1 || true
  done
  rm -f "$BUNDLE_DIR"/macos/rw.*.dmg "$BUNDLE_DIR"/dmg/rw.*.dmg 2>/dev/null || true

  say "Bundling .app and .dmg"
  local bundle_status=0
  cargo tauri build "${args[@]}" || bundle_status=$?

  local app
  app="$(find "$BUNDLE_DIR/macos" -maxdepth 1 -name '*.app' -print -quit 2>/dev/null || true)"
  [[ -n "$app" ]] || die "the build produced no .app"

  # Ad-hoc sign so Gatekeeper does not refuse to launch a locally built app.
  # A real release needs a Developer ID certificate and notarisation; see README.
  if [[ -z "${APPLE_SIGNING_IDENTITY:-}" ]]; then
    say "Ad-hoc signing $(basename "$app")"
    codesign --force --deep --sign - "$app" 2>/dev/null \
      || warn "ad-hoc signing failed; the .app may need a right-click → Open on first launch"
  fi

  # The .app is built and signed by now; only the disk image can still be
  # missing. Tauri's bundle_dmg.sh styles the volume through the Finder and
  # then unmounts it, and the Finder does not always let go in time —
  # "Resource busy", and the whole build reports failure over a step that has
  # nothing to do with the application. Make the image ourselves instead, from
  # the signed .app, which needs no Finder and no mounted volume at all.
  local dmg
  dmg="$(find "$BUNDLE_DIR/dmg" -maxdepth 1 -name '*.dmg' ! -name 'rw.*.dmg' -print -quit 2>/dev/null || true)"
  if [[ -z "$dmg" ]]; then
    (( bundle_status == 0 )) || warn "the bundler could not finish the .dmg; building it directly"
    make_dmg "$app" || die "could not build the .dmg"
  elif (( bundle_status != 0 )); then
    die "cargo tauri build failed"
  fi
}

# Build a .dmg from a finished .app: the application and the customary link to
# /Applications, compressed in one pass. Plain by design — no background image
# and no window layout, because those are what need the Finder.
make_dmg() {
  local app="$1"
  local name version arch staging out
  name="$(basename "$app" .app)"
  version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' src-tauri/tauri.conf.json | head -1)"
  # Name the file the way the bundler would have, so a recovered image is not
  # something the release notes have to explain: arm64 is aarch64 here.
  arch="$(uname -m)"; [[ "$arch" == "arm64" ]] && arch="aarch64"
  out="$BUNDLE_DIR/dmg/${name}_${version:-0.0.0}_${arch}.dmg"

  # A previous run's scratch images and volumes would be picked up as the app
  # to copy, or hold the name we are about to write.
  rm -f "$BUNDLE_DIR"/macos/rw.*.dmg "$BUNDLE_DIR"/dmg/rw.*.dmg "$out" 2>/dev/null || true

  staging="$(mktemp -d)"
  trap 'rm -rf "$staging"' RETURN
  cp -R "$app" "$staging/"
  ln -s /Applications "$staging/Applications"

  mkdir -p "$BUNDLE_DIR/dmg"
  say "Building $(basename "$out")"
  hdiutil create -quiet -srcfolder "$staging" -volname "$name" \
    -fs HFS+ -format UDZO -imagekey zlib-level=9 "$out"
}

# Debian and Ubuntu. The bundler needs the WebKit and GTK development packages,
# because the window easySSH draws in is the system's own web view rather than
# one it ships. Say which packages are missing rather than letting the linker
# fail three minutes into a build.
build_linux() {
  [[ "$HOST" == "linux" ]] || die "The .deb must be built on Debian or Ubuntu."

  local missing=()
  if command -v pkg-config >/dev/null; then
    pkg-config --exists webkit2gtk-4.1 || missing+=(libwebkit2gtk-4.1-dev)
    pkg-config --exists gtk+-3.0       || missing+=(libgtk-3-dev)
  else
    missing+=(pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev)
  fi
  command -v patchelf >/dev/null || missing+=(patchelf)

  if (( ${#missing[@]} )); then
    die "Missing build dependencies. On Debian or Ubuntu:
       sudo apt-get install -y ${missing[*]} librsvg2-dev libssl-dev \
         libayatana-appindicator3-dev build-essential curl wget file"
  fi

  say "Bundling .deb"
  cargo tauri build --bundles deb
}

build_windows() {
  if [[ "$HOST" != "windows" ]]; then
    die "Windows installers must be built on Windows (NSIS and WiX do not run here).
       Run scripts/build.ps1 on a Windows machine, or push a tag and let
       .github/workflows/release.yml build both platforms."
  fi
  say "Bundling .exe and .msi"
  cargo tauri build --bundles nsis,msi
}

case "$TARGET" in
  macos)   build_macos ;;
  windows) build_windows ;;
  linux)   build_linux ;;
  *)       die "Unknown target '$TARGET'. Use: macos, windows, linux, all." ;;
esac

# ── report ───────────────────────────────────────────────────────────────────

say "Artifacts"
found=0
while IFS= read -r f; do
  found=1
  size="$(du -h "$f" | cut -f1 | tr -d ' ')"
  printf '   %s%s%s  %s(%s)%s\n' "$GREEN" "$f" "$OFF" "$DIM" "$size" "$OFF"
done < <(find "$BUNDLE_DIR" -maxdepth 2 \
           \( -name '*.dmg' -o -name '*.msi' -o -name '*-setup.exe' -o -name '*.AppImage' -o -name '*.deb' \) \
           ! -name 'rw.*.dmg' \
           2>/dev/null | sort)

if [[ "$found" == "0" ]]; then
  warn "No installers found under $BUNDLE_DIR"
  exit 1
fi

printf '\n%sDone.%s\n' "$GREEN$BOLD" "$OFF"
