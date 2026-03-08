#!/bin/sh
set -euo pipefail

REPO="0x63616c/tomb"
INSTALL_DIR="${TOMB_INSTALL:-$HOME/.tomb}/bin"

# ── Colours ────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    BOLD="\033[1m"
    GREEN="\033[32m"
    RED="\033[31m"
    RESET="\033[0m"
else
    BOLD="" GREEN="" RED="" RESET=""
fi

info()  { printf "${BOLD}%s${RESET}\n" "$*"; }
ok()    { printf "${GREEN}✓${RESET} %s\n" "$*"; }
error() { printf "${RED}error:${RESET} %s\n" "$*" >&2; exit 1; }

# ── Prerequisites ──────────────────────────────────────────────────────────
command -v curl >/dev/null 2>&1 || error "curl is required but not found"
command -v tar  >/dev/null 2>&1 || error "tar is required but not found"

# ── Detect platform ────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin) OS_NAME="apple-darwin" ;;
    Linux)  OS_NAME="unknown-linux-gnu" ;;
    *)      error "Unsupported OS: $OS (supported: macOS, Linux)" ;;
esac

# Detect Rosetta 2 (macOS ARM reporting as x86_64)
if [ "$OS" = "Darwin" ] && [ "$ARCH" = "x86_64" ]; then
    if sysctl -n sysctl.proc_translated 2>/dev/null | grep -q "^1$"; then
        ARCH="arm64"
    fi
fi

case "$ARCH" in
    x86_64)         ARCH_NAME="x86_64" ;;
    arm64|aarch64)  ARCH_NAME="aarch64" ;;
    *)              error "Unsupported architecture: $ARCH (supported: x86_64, arm64/aarch64)" ;;
esac

TARGET="${ARCH_NAME}-${OS_NAME}"

# ── Fetch latest release tag ───────────────────────────────────────────────
info "Fetching latest release..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

[ -n "$LATEST" ] || error "Could not determine latest release"

# ── Download and install ───────────────────────────────────────────────────
TARBALL="tomb-${LATEST}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${TARBALL}"

info "Downloading tomb ${LATEST} for ${TARGET}..."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$URL" -o "$TMP/$TARBALL" \
    || error "Download failed. Check that ${LATEST} has a build for ${TARGET}."

tar xzf "$TMP/$TARBALL" -C "$TMP" \
    || error "Failed to extract tarball"

mkdir -p "$INSTALL_DIR"
mv "$TMP/tomb" "$INSTALL_DIR/tomb"
chmod +x "$INSTALL_DIR/tomb"

ok "Installed tomb ${LATEST} to ${INSTALL_DIR}/tomb"

# ── PATH setup ─────────────────────────────────────────────────────────────
# Check if already on PATH
if command -v tomb >/dev/null 2>&1; then
    ok "tomb is already on your PATH"
    exit 0
fi

EXPORT_LINE="export PATH=\"\$PATH:${INSTALL_DIR}\""
SHELL_NAME="$(basename "${SHELL:-sh}")"

add_to_rc() {
    RC="$1"
    if [ -f "$RC" ] && grep -qF "$INSTALL_DIR" "$RC" 2>/dev/null; then
        ok "PATH already set in $RC"
    else
        printf '\n# tomb\n%s\n' "$EXPORT_LINE" >> "$RC"
        ok "Added to $RC"
    fi
}

case "$SHELL_NAME" in
    zsh)  add_to_rc "$HOME/.zshrc" ;;
    bash) add_to_rc "${BASH_ENV:-$HOME/.bashrc}" ;;
    fish)
        FISH_CONFIG="$HOME/.config/fish/config.fish"
        mkdir -p "$(dirname "$FISH_CONFIG")"
        if ! grep -qF "$INSTALL_DIR" "$FISH_CONFIG" 2>/dev/null; then
            printf '\n# tomb\nfish_add_path "%s"\n' "$INSTALL_DIR" >> "$FISH_CONFIG"
            ok "Added to $FISH_CONFIG"
        fi
        ;;
    *)
        printf "\nAdd this to your shell config:\n  %s\n" "$EXPORT_LINE"
        ;;
esac

printf "\nRestart your shell or run:\n  %s\n" "$EXPORT_LINE"
printf "\nVerify:\n  tomb --version\n"
