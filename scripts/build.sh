#!/usr/bin/env bash
# Build easySSH installers.
#
#   ./scripts/build.sh              # bundle for the machine you are on
#   ./scripts/build.sh macos        # .dmg + .app       (must run on macOS)
#   ./scripts/build.sh windows      # .exe + .msi       (must run on Windows, or see below)
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
  hdiutil info 2>/dev/null | awk -v proj="$ROOT" '
    /^image-path/ { img=$0; sub(/^image-path[ \t]*:[ \t]*/, "", img) }
    /^\/dev\/disk[0-9]+$/ { if (index(img, proj) && index(img, "rw.")) print $1 }
  ' | while read -r dev; do
    warn "detaching leftover disk image $dev"
    hdiutil detach "$dev" -force >/dev/null 2>&1 || true
  done
  rm -f "$BUNDLE_DIR"/macos/rw.*.dmg "$BUNDLE_DIR"/dmg/rw.*.dmg 2>/dev/null || true

  say "Bundling .app and .dmg"
  cargo tauri build "${args[@]}"

  # Ad-hoc sign so Gatekeeper does not refuse to launch a locally built app.
  # A real release needs a Developer ID certificate and notarisation; see README.
  local app
  app="$(find "$BUNDLE_DIR/macos" -maxdepth 1 -name '*.app' -print -quit 2>/dev/null || true)"
  if [[ -n "$app" && -z "${APPLE_SIGNING_IDENTITY:-}" ]]; then
    say "Ad-hoc signing $(basename "$app")"
    codesign --force --deep --sign - "$app" 2>/dev/null \
      || warn "ad-hoc signing failed; the .app may need a right-click → Open on first launch"
  fi
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
  linux)   say "Bundling for Linux"; cargo tauri build ;;
  *)       die "Unknown target '$TARGET'. Use: macos, windows, all." ;;
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
