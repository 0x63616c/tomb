# tombui - Product Spec & Design

## What We're Building

A terminal UI (TUI) application that wraps the tomb library. Separate binary (`tombui`), same Cargo workspace. Makes tomb approachable without memorizing CLI flags. Guided flows for every operation. The existing `tomb` CLI gains a `tomb ui` subcommand that execs `tombui`.

## Non-Technical Assumptions

- Primary audience: people who want to use tomb but don't want to memorize flags
- Not replacing the CLI, just layering on top
- Single-user, local only (no networked features)
- MVP scope: all 5 tomb operations (seal, open, verify, inspect, generate) in a TUI
- No file browser (too complex for MVP), text input for paths with tab completion later

## Technical Assumptions

- Rust, `ratatui` 0.29+ and `crossterm` for terminal abstraction
- Separate crate: `tombui/` in a Cargo workspace with the root `tomb` crate
- Depends on `tomb` as a path dependency for the library API
- `tomb ui` subcommand execs `tombui` binary (fails gracefully if not installed)
- Passphrase entry uses crossterm raw mode (no echo), not rpassword
- KDF progress is shown as a spinner/timer (tomb lib doesn't expose progress callbacks yet, so we estimate time)
- All tomb library calls happen on a background thread to keep the UI responsive

## Architecture

### Workspace Layout

```
Cargo.toml          # workspace root (adds [workspace] section)
src/                # existing tomb lib + CLI
tombui/
  Cargo.toml        # depends on tomb = { path = ".." }
  src/
    main.rs         # entry point, App struct, main loop
    app.rs          # App state machine
    ui.rs           # render functions
    screens/
      mod.rs
      home.rs       # action menu
      seal.rs       # seal wizard
      open.rs       # open wizard
      verify.rs     # verify flow
      inspect.rs    # inspect viewer
      generate.rs   # passphrase generator
    widgets/
      mod.rs
      passphrase.rs # masked input with strength indicator
      progress.rs   # spinner + elapsed time
      header.rs     # visual header display (used by inspect)
```

### App State Machine

```
Home -> Seal(step) | Open(step) | Verify(step) | Inspect(step) | Generate(step)
     <- (Esc returns to Home from any screen)
```

Each flow is a multi-step wizard:

**Seal:** SelectFile -> EnterPassphrase -> ConfirmPassphrase -> Sealing(progress) -> Done
**Open:** SelectFile -> EnterPassphrase -> Opening(progress) -> Done
**Verify:** SelectFile -> EnterPassphrase -> Verifying(progress) -> Done/Failed
**Inspect:** SelectFile -> ShowHeader
**Generate:** ShowPassphrase -> ConfirmPassphrase -> Done

### Screen Layout

```
┌─ tombui ─────────────────────────────────────────┐
│                                                   │
│   Title / breadcrumb                              │
│                                                   │
│   Main content area                               │
│   (wizard steps, forms, results)                  │
│                                                   │
│                                                   │
│                                                   │
├───────────────────────────────────────────────────┤
│ q: quit  esc: back  enter: confirm  ?: help       │
└───────────────────────────────────────────────────┘
```

### Home Screen

Centered action menu with vim-style j/k navigation:

```
  tomb - encrypt anything

  > Seal a file
    Open a .tomb file
    Verify a .tomb file
    Inspect a .tomb file
    Generate a passphrase

  [j/k to move, Enter to select, q to quit]
```

### Key Bindings

- `j`/`k` or arrow keys: navigate
- `Enter`: select/confirm
- `Esc`: back to previous step / home
- `q`: quit (from home screen)
- `?`: toggle help overlay
- `Tab`: cycle focus (when multiple inputs)

### Background Threading

The tomb library does blocking work (KDF takes ~5 seconds). We run these on a separate thread:

```rust
enum WorkerResult {
    SealComplete(Result<PathBuf>),
    OpenComplete(Result<(Vec<u8>, String)>),
    VerifyComplete(Result<()>),
}
```

The main loop polls a `mpsc::Receiver<WorkerResult>` each tick alongside terminal events.

### Passphrase Input Widget

- Masked by default (dots)
- Toggle visibility with Ctrl+V
- Word count shown live: "12/21 words"
- On seal: two-pass entry (enter, then confirm)
- On generate: show in cleartext, then require re-entry

### Inspect View

Visual breakdown of the header:

```
  File: backup.tomb
  Format: v1.0

  KDF Chain (2 stages):
    1. scrypt (0x01)    1 GB memory
    2. argon2id (0x02)  1 GB memory

  Cipher Layers (3):
    1. Twofish-256-CTR  (0x01)  nonce: 16 bytes
    2. AES-256-CTR      (0x02)  nonce: 16 bytes
    3. XChaCha20        (0x03)  nonce: 24 bytes
```

### Error Handling

- All tomb::Error variants shown as a styled error block at the bottom
- User can press Enter/Esc to dismiss and retry
- DecryptionFailed shows generic "Decryption failed" (matches CLI behavior)

### `tomb ui` Subcommand

Added to existing CLI in `src/cli.rs`:

```rust
Command::Ui => {
    // exec tombui, fail gracefully if not installed
    let status = std::process::Command::new("tombui").status();
    match status {
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(_) => eprintln!("tombui is not installed. Install it with: cargo install --path tombui/"),
    }
}
```

## Dependencies (tombui crate)

- `tomb` (path = "..")
- `ratatui` 0.29
- `crossterm` 0.28
- `zeroize` 1 (passphrase handling)

## Not Included in MVP

- File browser / directory traversal
- Tab completion for file paths
- Drag-and-drop
- Mouse support
- Config file / themes
- Multi-file batch operations
- Progress callbacks from tomb lib (future enhancement)
