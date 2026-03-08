# Version SHA, Install Script, and Self-Update Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add git SHA to `--version` output, ship a `curl | bash` install script, and add a `tomb update` command.

**Architecture:** Three independent features. `build.rs` embeds git SHA and target triple at compile time. `install.sh` lives in the repo root and downloads the right tarball from GitHub Releases. `tomb update` shells out to `curl` and `tar` (zero new deps) to replace its own binary atomically.

**Tech Stack:** Rust `build.rs`, POSIX `sh`, GitHub Releases API, `std::process::Command` for curl/tar subprocess.

---

## Task 1: build.rs — embed git SHA and target triple

**Files:**
- Create: `build.rs`

### Step 1: Create build.rs

```rust
use std::process::Command;

fn main() {
    // Rerun if git HEAD changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");

    // Git SHA (short, 7 chars). Falls back to "unknown" if git unavailable.
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=TOMB_GIT_SHA={sha}");

    // Target triple (e.g. "aarch64-apple-darwin"). Used by `tomb update`.
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=TOMB_TARGET={target}");
}
```

### Step 2: Verify build compiles and SHA is captured

```bash
cargo build 2>&1 | head -5
cargo run -- --version
```

Expected: compiles cleanly. `--version` still shows `tomb 0.1.0` (we wire it up in Task 2).

### Step 3: Commit

```bash
git add build.rs
git commit -m "build: add build.rs to embed git SHA and target triple"
```

---

## Task 2: Wire SHA into clap version output

**Files:**
- Modify: `src/cli.rs` (lines 13–18, the `#[command(...)]` block)

### Step 1: Update the #[command] attribute

In `src/cli.rs`, change the `#[command]` block on `Cli`:

```rust
#[derive(Parser)]
#[command(
    name = "tomb",
    version,
    long_version = concat!(
        env!("CARGO_PKG_VERSION"),
        " (",
        env!("TOMB_GIT_SHA"),
        ")"
    ),
    about = "Encrypt anything with a passphrase. Recover it decades later.",
    arg_required_else_help = true,
    after_help = "Examples:
  tomb generate                          Generate a 21-word passphrase
  tomb seal secrets.json                 Encrypt with default output (secrets.tomb)
  tomb seal secrets.json -o backup.tomb  Encrypt with custom output name
  tomb seal data.tar --note \"march 2026\" Encrypt with a note
  tomb open backup.tomb                  Decrypt to original filename
  tomb open backup.tomb -o restored.json Decrypt to custom path
  tomb verify backup.tomb                Confirm file is decryptable
  tomb inspect backup.tomb               View header without passphrase"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
```

Note: `version` (no value) → shows `CARGO_PKG_VERSION` for `-V`. `long_version` → shows version + SHA for `--version`. This gives:
- `tomb -V` → `tomb 0.1.0`
- `tomb --version` → `tomb 0.1.0 (a3bf803)`

### Step 2: Test both flags

```bash
cargo run -- -V
# Expected: tomb 0.1.0

cargo run -- --version
# Expected: tomb 0.1.0 (a3bf803)   ← real SHA will differ
```

### Step 3: Run tests to make sure nothing broke

```bash
cargo test --lib
# Expected: test result: ok. 104 passed
```

### Step 4: Commit

```bash
git add src/cli.rs
git commit -m "feat: add git SHA to --version output"
```

---

## Task 3: Write install.sh

**Files:**
- Create: `install.sh`

The script installs to `~/.tomb/bin`, overrides with `$TOMB_INSTALL`. Detects shell and appends to rc file. Silently overwrites if already installed (install = upgrade).

### Step 1: Create install.sh

```sh
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
```

### Step 2: Make it executable and run shellcheck

```bash
chmod +x install.sh
shellcheck install.sh 2>&1
# Expected: no errors (install shellcheck with: brew install shellcheck)
```

### Step 3: Smoke test locally (dry run — inspect only, don't actually pipe to sh)

```bash
bash -n install.sh
# Expected: no syntax errors (bash -n = parse only, don't execute)
```

### Step 4: Commit

```bash
git add install.sh
git commit -m "feat: add curl-pipe-bash install script"
```

---

## Task 4: Update release.yml to include install.sh

**Files:**
- Modify: `.github/workflows/release.yml`

The release workflow should upload `install.sh` as a release asset so users can pin to a specific version. The `curl | bash` URL also works against the main branch for always-latest.

### Step 1: Add install.sh to release assets

In the `release` job's `Create GitHub Release` step, add `install.sh` to the `files:` list and update the body to include the install one-liner:

Find this section in `.github/workflows/release.yml`:

```yaml
          body: |
            ## Install

            Download the archive for your platform, extract, and move to your PATH:

            ```bash
            tar xzf tomb-${{ steps.tag.outputs.TAG }}-<TARGET>.tar.gz
            sudo mv tomb /usr/local/bin/
            ```
```

Replace with:

```yaml
          body: |
            ## Install

            ```bash
            curl -fsSL https://raw.githubusercontent.com/0x63616c/tomb/main/install.sh | bash
            ```

            Or download a specific platform binary from the assets below and extract manually.

            ## Verify checksums

            ```bash
            sha256sum -c SHA256SUMS --ignore-missing
            # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
            ```
```

And update the `files:` block to include `install.sh`:

```yaml
          files: |
            artifacts/tomb-*.tar.gz
            SHA256SUMS
            install.sh
```

### Step 2: Verify YAML is valid

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"
# Expected: no output (valid YAML)
```

### Step 3: Commit

```bash
git add .github/workflows/release.yml
git commit -m "ci: add install.sh to release assets and update install instructions"
```

---

## Task 5: Add `tomb update` subcommand

**Files:**
- Modify: `src/cli.rs` — add `Update` variant to `Command` enum and handle it in `run()`

No new dependencies. Uses `curl` subprocess for download and `tar` subprocess for extraction. Parses GitHub API response with simple string search (no JSON dep).

### Step 1: Add Update to the Command enum

In `src/cli.rs`, add to the `Command` enum after `Generate`:

```rust
/// Update tomb to the latest release
Update,
```

### Step 2: Add the update handler in run()

Add to the `match cli.command` block in `run()`:

```rust
Command::Update => {
    run_update()?;
}
```

### Step 3: Implement run_update()

Add this function to `src/cli.rs` (before `pub fn run()`):

```rust
fn run_update() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let target = env!("TOMB_TARGET");

    // Fetch latest release tag from GitHub API
    let api_url = "https://api.github.com/repos/0x63616c/tomb/releases/latest";
    let response = std::process::Command::new("curl")
        .args(["-fsSL", "--user-agent", "tomb-updater", api_url])
        .output()
        .map_err(|e| Error::Io(e))?;

    if !response.status.success() {
        return Err(Error::Format("Failed to fetch latest release info".into()));
    }

    let body = String::from_utf8_lossy(&response.stdout);
    let tag = extract_json_string(&body, "tag_name")
        .ok_or_else(|| Error::Format("Could not parse release tag from GitHub API".into()))?;

    let latest = tag.trim_start_matches('v');

    if latest == current {
        println!("Already up to date ({})", current);
        return Ok(());
    }

    println!("Updating {} -> {}...", current, latest);

    // Download tarball to temp dir
    let tarball_name = format!("tomb-{}-{}.tar.gz", tag, target);
    let url = format!(
        "https://github.com/0x63616c/tomb/releases/download/{}/{}",
        tag, tarball_name
    );

    let tmp = std::env::temp_dir().join(format!("tomb-update-{}", latest));
    std::fs::create_dir_all(&tmp)?;

    let tarball_path = tmp.join(&tarball_name);

    let download = std::process::Command::new("curl")
        .args(["-fsSL", "-o", tarball_path.to_str().unwrap(), &url])
        .status()
        .map_err(|e| Error::Io(e))?;

    if !download.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(Error::Format(format!(
            "Failed to download {}. Is {} a supported platform?",
            url, target
        )));
    }

    // Extract binary
    let extract = std::process::Command::new("tar")
        .args(["xzf", tarball_path.to_str().unwrap(), "-C", tmp.to_str().unwrap()])
        .status()
        .map_err(|e| Error::Io(e))?;

    if !extract.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(Error::Format("Failed to extract tarball".into()));
    }

    // Atomically replace own binary
    let new_binary = tmp.join("tomb");
    let current_exe = std::env::current_exe().map_err(|e| Error::Io(e))?;

    // Write to a sibling temp file then rename (atomic on POSIX)
    let tmp_exe = current_exe.with_extension("tmp");
    std::fs::copy(&new_binary, &tmp_exe)?;
    std::fs::rename(&tmp_exe, &current_exe)?;

    let _ = std::fs::remove_dir_all(&tmp);

    println!("Updated to {}. Run 'tomb --version' to confirm.", latest);
    Ok(())
}

/// Extract a string value from JSON by key. Simple, no dep.
/// Works for flat string fields like `"tag_name": "v0.1.0"`.
fn extract_json_string<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let search = format!("\"{}\"", key);
    let key_pos = json.find(&search)?;
    let after_key = &json[key_pos + search.len()..];
    // Skip whitespace and colon
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let value_start = &after_colon[1..];
    let value_end = value_start.find('"')?;
    Some(&value_start[..value_end])
}
```

### Step 4: Verify it compiles

```bash
cargo build 2>&1
# Expected: Compiling tomb... Finished
```

### Step 5: Smoke test (will hit real GitHub API)

```bash
cargo run -- update
# Expected (when already latest): "Already up to date (0.1.0)"
# Or: "Updating 0.1.0 -> 0.x.x..." if a newer release exists
```

### Step 6: Run all tests

```bash
cargo test --lib
# Expected: test result: ok. 104 passed
```

### Step 7: Commit

```bash
git add src/cli.rs
git commit -m "feat: add tomb update command for self-update"
```

---

## Task 6: Final integration check and push

### Step 1: Run full test suite

```bash
cargo test
# Expected: all tests pass
```

### Step 2: Check clippy

```bash
cargo clippy -- -D warnings
# Expected: no warnings
```

### Step 3: Check formatting

```bash
cargo fmt --check
# Expected: no output
```

### Step 4: Manual end-to-end check

```bash
cargo run -- --version
# Expected: tomb 0.1.0 (abc1234)

cargo run -- -V
# Expected: tomb 0.1.0

cargo run -- update
# Expected: "Already up to date" or update flow

bash -n install.sh
# Expected: no syntax errors
```

### Step 5: Push

```bash
git push
```

---

## Notes

**install.sh URL:** Once merged to main, users can run:
```bash
curl -fsSL https://raw.githubusercontent.com/0x63616c/tomb/main/install.sh | bash
```

**TOMB_TARGET in update:** The `env!("TOMB_TARGET")` macro embeds the compile-time target triple (e.g. `aarch64-apple-darwin`). This means `tomb update` downloads the binary for the exact same platform the running binary was built for. No runtime platform detection needed.

**Atomic binary replacement:** On macOS and Linux, `rename()` (called by `fs::rename`) is atomic within the same filesystem. Writing to a `.tmp` sibling file first ensures the old binary is still valid if the copy fails mid-way.

**No new dependencies added.** `curl` and `tar` are shelled out — both guaranteed present on any machine that ran the install script.
