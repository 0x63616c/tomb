# tomb - Future Ideas

Things worth exploring. Not committed, not planned. Just interesting.

---

## Reed-Solomon Error Correction

Bit rot is the real enemy for multi-decade storage. A single flipped bit on a USB drive or degraded cloud storage makes the entire file unrecoverable. Reed-Solomon ECC would let tomb self-heal from partial corruption. More likely to save your data than a 4th cipher layer.

## Self-Describing Archive

If someone finds a .tomb file in 30 years and the tomb binary is gone, they have an opaque blob. Embed a compressed plaintext format spec in the public header area, readable without a passphrase. The "Rosetta Stone" principle: the file contains its own decoding instructions.

## Verifiable Delay Functions (VDFs)

Cutting-edge crypto (2018+). Memory-hard KDFs defend against parallelism (need 2GB per guess). VDFs defend against sequential speedup. Even with unlimited parallel hardware, each guess requires X seconds of inherently sequential computation. scrypt and Argon2id are memory-hard but not provably sequential. A VDF layer would mean: even if someone breaks the memory-hardness of both KDFs, they still can't go faster than wall-clock time per guess.

## STREAM Construction

Formalize the 64KB chunked encryption using the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizar 2015). Prevents chunk reordering, duplication, and truncation within the authenticated layer. Used by `age` and libsodium. Current design mentions chunk index in nonce but doesn't specify full STREAM semantics.

## Honey Encryption

Wrong passphrase produces plausible-looking fake data instead of garbage. Brute-force attacker can't distinguish correct from incorrect decryption without evaluating every candidate. Published by Juels & Ristenpart (2014). Hard for arbitrary files, feasible for structured formats (JSON, text, key files).

## Deniable / Hidden Volumes

Two passphrases: real one decrypts real data, decoy one decrypts plausible fake data. File is indistinguishable from a single-volume file. VeraCrypt does this for disk encryption. Relevant when the existence of encrypted data is already known (TOMB magic bytes are visible).

## Heartbeat / Proof-of-Life

`tomb heartbeat` logs a timestamp each time you successfully verify a file. Warns if you haven't verified in N months. Not crypto, just operational discipline for decades-long backups. Could integrate with cron or launchd.

## tombui: Terminal UI

A dedicated TUI application built on top of the tomb library. Separate binary (`tombui`) that provides a rich interactive interface for managing .tomb files without memorizing CLI flags.

**Why:** The CLI is great for scripting and power users, but a TUI makes tomb more approachable. Browse files, seal/open with guided prompts, inspect headers visually, monitor KDF progress with real-time bars. All without leaving the terminal.

**Possible features:**
- File browser for selecting input files and .tomb archives
- Guided seal flow: pick file, enter passphrase (with strength indicator), watch progress
- Inspect view: visual breakdown of header, KDF params, cipher layers, file metadata
- Verify status dashboard for multiple .tomb files at once
- Passphrase generation with copy-to-clipboard
- Keyboard-driven (vim-style navigation)

**Tech:** Likely `ratatui` + `crossterm`. Separate crate in a workspace (`tombui/`), depends on `tomb` as a library. Keeps the core crate dependency-free of TUI concerns.
