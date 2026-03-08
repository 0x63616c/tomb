# Enum IDs + Config Refactor Design

Date: 2026-03-07

## Problem

1. Raw `u8` IDs for KDFs and ciphers with `_ =>` wildcards. Adding a new algorithm silently falls through instead of causing a compile error.
2. Library hardcodes production KDF params. CLI has no control. Tests use `_with_params` variant functions to bypass.
3. KDF params in header are display-friendly (memory_mb) not native (log_n for scrypt). Can't reconstruct KDFs from header alone.
4. ID namespace is cramped (KDFs 0x10-0x1F = 16 slots, ciphers 0x20-0x2F = 16 slots).

## Design

### 1. Type-safe enums

Two separate enums with `repr(u8)`. No shared namespace, each gets 256 slots:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherId {
    Twofish = 0x01,
    Aes     = 0x02,
    XChaCha = 0x03,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KdfId {
    Scrypt   = 0x01,
    Argon2id = 0x02,
}
```

`TryFrom<u8>` is the single deserialization boundary where `_ => Err()` exists. Every other match uses the enum without wildcards. Adding a new variant causes compile errors at every match site.

### 2. SealConfig

Library takes config, CLI constructs it:

```rust
pub enum KdfParams {
    Scrypt { log_n: u8, r: u32, p: u32 },
    Argon2id { memory_kib: u32, iterations: u32, parallelism: u32 },
}

impl KdfParams {
    fn id(&self) -> KdfId { ... }
}

pub struct SealConfig {
    pub kdf_chain: Vec<KdfParams>,
    pub cipher_ids: Vec<CipherId>,
}

impl SealConfig {
    pub fn production() -> Self { ... }
    pub fn test() -> Self { ... }
}
```

`seal(input, output, passphrase, note, config)` is the only seal function. No `_with_params` variants.

### 3. Header format change (native KDF params)

KDF entries store native params per algorithm (variable-length, ID determines size):

- Scrypt: `id(1) + log_n(1) + r(4 LE) + p(4 LE)` = 10 bytes
- Argon2id: `id(1) + memory_kib(4 LE) + iterations(4 LE) + parallelism(4 LE)` = 13 bytes

`KdfParams` has `serialize()` and `deserialize(data) -> Result<(Self, usize)>` methods.

`KdfDescriptor` struct is removed, replaced by `KdfParams`.

### 4. Header-driven open

```rust
pub fn open_file(path: &Path, passphrase: &Passphrase) -> Result<OpenedFile>
```

Single function. Reads KDF IDs and native params from header, reconstructs KDF implementations. Reads cipher IDs from header, builds pipeline. No params needed from caller.

Tests seal with test params (written to header), open reads them back automatically.

### 5. Removals

- `seal_with_params()` -> `seal()` takes `SealConfig`
- `derive_keys()` / `derive_keys_with_params()` -> `derive_keys(passphrase, pipeline, kdf_chain: &[KdfParams])`
- `open_file_with_params()` -> `open_file()` reads from header
- `verify_sealed()` loses scrypt/argon2 params, just takes passphrase + path
- `kdf_by_id()` -> removed (KdfParams deserialization replaces it)
- `KdfDescriptor` -> removed (replaced by KdfParams)
- `cipher_by_id()` takes `CipherId` instead of `u8`

### 6. Version constants

```rust
pub const FORMAT_VERSION_MAJOR: u8 = 1;
pub const FORMAT_VERSION_MINOR: u8 = 0;
```

Format stays v1.0 (nothing shipped yet).

### 7. Trait changes

- `CipherLayer::id()` returns `CipherId` (was `u8`)
- `Derive::id()` returns `KdfId` (was `u8`)

## Decisions

- Separate enums (not shared) so wildcard-free matches work everywhere
- IDs renumbered from 1 (no wasted range, 256 slots per category)
- KdfParams enum doubles as config and serialization format
- Variable-length KDF entries in header (ID determines byte count)
- No backward compatibility needed (format not shipped)
