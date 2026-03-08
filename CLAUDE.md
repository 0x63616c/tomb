# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build                    # Build debug
cargo build --release          # Build release (stripped, LTO)
cargo test                     # Run all tests (unit + integration)
cargo test --lib               # Unit tests only
cargo test --test integration  # Integration tests only
cargo test key::derive         # Run tests in a specific module
cargo test seal_and_open       # Run a single test by name
cargo clippy                   # Lint
cargo fmt --check              # Check formatting
```

Tests use tiny KDF params (`ScryptDerive::test()`, `Argon2idDerive::test()`) and run in milliseconds. Production functions (`seal`, `open_file`, `derive_keys`) use 1GB+ memory params and take ~5 seconds. Never use production params in tests.

## Architecture

**Encryption pipeline:** passphrase -> chained KDF (scrypt then Argon2id) -> master key -> HKDF-SHA256 per-layer key expansion -> 3 cipher layers (Twofish-256-CTR, AES-256-CTR, XChaCha20), each with independent HMAC-SHA256 authentication (Encrypt-then-MAC).

### Module Layout

- `src/lib.rs` - Public API: `prepare_payload`, `derive_keys`, `encrypt_and_write`, `seal`, `open_file`, `verify_sealed`, `inspect_file`. Also defines `Error` enum and `Result` type.
- `src/cli.rs` - CLI (clap): `seal`, `open`, `verify`, `inspect`, `generate`. Policy enforcement layer (21-word passphrase, production KDF params).
- `src/cipher/` - `CipherLayer` trait + implementations (twofish.rs, aes.rs, xchacha.rs). `lookup.rs` has `cipher_by_id()` match function.
- `src/key/` - `MasterKey`, `LayerKey`, `Passphrase`, `Commitment` types (all `Zeroize`). `derive.rs` has `Derive` trait, `ScryptDerive`, `Argon2idDerive`, `chain_derive()`. `expand.rs` has `LayerState` (bundles encrypt_key + mac_key + nonce) and `expand_layer_keys()`. `commit.rs` has HMAC-SHA256 key commitment.
- `src/pipeline/` - `Pipeline` orchestrates seal/open across all cipher layers. `envelope.rs` handles per-layer binary envelopes with HMAC verification.
- `src/format/` - Binary format: `PublicHeader` (header.rs), `InnerHeader` (inner.rs, encrypted), PADME padding (padding.rs).
- `src/passphrase/` - EFF diceware validation and generation. `wordlist.rs` has the 7,776-word list.
- `tests/integration.rs` - Full round-trip tests (seal -> open, tamper detection, wrong passphrase, large/empty files).
- `docs/` - REQUIREMENTS.md, DESIGN-DECISIONS.md, FUTURE.md, how-long-to-crack.md, plans/.

### Key Patterns

- **Library/CLI split:** Library accepts params for testing, CLI locks everything to production values. Use `seal_with_params` / `open_file_with_params` in tests.
- **ID namespaces:** KDFs are 0x1x (scrypt=0x10, argon2id=0x11), ciphers are 0x2x (twofish=0x20, aes=0x21, xchacha=0x22).
- **Match-based lookup** (no HashMap): `cipher_by_id()` and `kdf_by_id()` use match statements.
- **LayerState** bundles encrypt_key + mac_key + nonce per layer (no parallel arrays).
- **All sensitive types** use `Zeroize`/`ZeroizeOnDrop`. `LayerKey` and `MasterKey` are `[u8; 32]`, not `Vec<u8>`.
- **Constant-time** comparisons via `subtle::ConstantTimeEq` for all secret-dependent checks.

## Crypto Constraints

- All three cipher layers use the same pattern: CTR/stream encrypt + HMAC-SHA256. No mixed AEAD.
- Use `chacha20` crate (stream cipher), NOT `chacha20poly1305`.
- PADME padding uses integer math only, no floats.
- HKDF labels follow pattern: `tomb-{cipher-name}` for encrypt key, `tomb-{cipher-name}-mac` for MAC key.
- Single `DecryptionFailed` error variant for all auth/decrypt failures (uniform error messages).
