# Enum IDs + Config Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace raw u8 IDs with exhaustive enums, make the library config-driven, and make open_file header-driven.

**Architecture:** Two separate enums (CipherId, KdfId) with TryFrom<u8> as the only wildcard boundary. KdfParams enum stores native algorithm params and handles its own serialization. SealConfig wraps KDF + cipher config. Library takes config, CLI constructs it, open reads from header.

**Tech Stack:** Rust, no new dependencies.

---

### Task 1: Add CipherId and KdfId enums

**Files:**
- Modify: `src/cipher/mod.rs` (add CipherId enum)
- Modify: `src/key/derive.rs` (add KdfId enum)

**Step 1: Write tests for CipherId**

Add to bottom of `src/cipher/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_id_try_from_valid() {
        assert_eq!(CipherId::try_from(0x01).unwrap(), CipherId::Twofish);
        assert_eq!(CipherId::try_from(0x02).unwrap(), CipherId::Aes);
        assert_eq!(CipherId::try_from(0x03).unwrap(), CipherId::XChaCha);
    }

    #[test]
    fn cipher_id_try_from_invalid() {
        assert!(CipherId::try_from(0x00).is_err());
        assert!(CipherId::try_from(0xFF).is_err());
    }

    #[test]
    fn cipher_id_round_trip() {
        for id in [CipherId::Twofish, CipherId::Aes, CipherId::XChaCha] {
            assert_eq!(CipherId::try_from(id as u8).unwrap(), id);
        }
    }

    #[test]
    fn cipher_id_display() {
        assert_eq!(CipherId::Twofish.name(), "twofish-256-ctr + hmac-sha256");
        assert_eq!(CipherId::Aes.name(), "aes-256-ctr + hmac-sha256");
        assert_eq!(CipherId::XChaCha.name(), "xchacha20 + hmac-sha256");
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test cipher::tests --lib`
Expected: FAIL (CipherId not defined)

**Step 3: Implement CipherId**

Add to `src/cipher/mod.rs` before the trait definition:

```rust
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CipherId {
    Twofish = 0x01,
    Aes     = 0x02,
    XChaCha = 0x03,
}

impl CipherId {
    pub fn name(&self) -> &'static str {
        match self {
            CipherId::Twofish => "twofish-256-ctr + hmac-sha256",
            CipherId::Aes => "aes-256-ctr + hmac-sha256",
            CipherId::XChaCha => "xchacha20 + hmac-sha256",
        }
    }
}

impl TryFrom<u8> for CipherId {
    type Error = Error;
    fn try_from(id: u8) -> Result<Self> {
        match id {
            0x01 => Ok(Self::Twofish),
            0x02 => Ok(Self::Aes),
            0x03 => Ok(Self::XChaCha),
            _ => Err(Error::UnknownLayer(id)),
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test cipher::tests --lib`
Expected: PASS

**Step 5: Write tests for KdfId**

Add to `src/key/derive.rs` in the existing test module:

```rust
#[test]
fn kdf_id_try_from_valid() {
    assert_eq!(KdfId::try_from(0x01).unwrap(), KdfId::Scrypt);
    assert_eq!(KdfId::try_from(0x02).unwrap(), KdfId::Argon2id);
}

#[test]
fn kdf_id_try_from_invalid() {
    assert!(KdfId::try_from(0x00).is_err());
    assert!(KdfId::try_from(0xFF).is_err());
}

#[test]
fn kdf_id_round_trip() {
    for id in [KdfId::Scrypt, KdfId::Argon2id] {
        assert_eq!(KdfId::try_from(id as u8).unwrap(), id);
    }
}

#[test]
fn kdf_id_display() {
    assert_eq!(KdfId::Scrypt.name(), "scrypt");
    assert_eq!(KdfId::Argon2id.name(), "argon2id");
}
```

**Step 6: Implement KdfId**

Add to `src/key/derive.rs` before the Derive trait:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KdfId {
    Scrypt   = 0x01,
    Argon2id = 0x02,
}

impl KdfId {
    pub fn name(&self) -> &'static str {
        match self {
            KdfId::Scrypt => "scrypt",
            KdfId::Argon2id => "argon2id",
        }
    }
}

impl TryFrom<u8> for KdfId {
    type Error = Error;
    fn try_from(id: u8) -> Result<Self> {
        match id {
            0x01 => Ok(Self::Scrypt),
            0x02 => Ok(Self::Argon2id),
            _ => Err(Error::UnknownKdf(id)),
        }
    }
}
```

**Step 7: Run all tests**

Run: `cargo test --lib`
Expected: PASS (new tests pass, existing tests unaffected)

**Step 8: Commit**

```bash
git add src/cipher/mod.rs src/key/derive.rs
git commit -m "feat: add CipherId and KdfId enums with TryFrom<u8>"
git push
```

---

### Task 2: Add KdfParams enum

**Files:**
- Modify: `src/key/derive.rs` (add KdfParams enum with serialization)

**Step 1: Write tests for KdfParams**

Add to test module in `src/key/derive.rs`:

```rust
#[test]
fn kdf_params_scrypt_id() {
    let params = KdfParams::Scrypt { log_n: 20, r: 8, p: 1 };
    assert_eq!(params.id(), KdfId::Scrypt);
}

#[test]
fn kdf_params_argon2id_id() {
    let params = KdfParams::Argon2id { memory_kib: 1_048_576, iterations: 4, parallelism: 4 };
    assert_eq!(params.id(), KdfId::Argon2id);
}

#[test]
fn kdf_params_scrypt_serialize_round_trip() {
    let params = KdfParams::Scrypt { log_n: 20, r: 8, p: 1 };
    let bytes = params.serialize();
    assert_eq!(bytes[0], KdfId::Scrypt as u8);
    let (parsed, consumed) = KdfParams::deserialize(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, params);
}

#[test]
fn kdf_params_argon2id_serialize_round_trip() {
    let params = KdfParams::Argon2id { memory_kib: 1_048_576, iterations: 4, parallelism: 4 };
    let bytes = params.serialize();
    assert_eq!(bytes[0], KdfId::Argon2id as u8);
    let (parsed, consumed) = KdfParams::deserialize(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, params);
}

#[test]
fn kdf_params_to_derive_scrypt() {
    let params = KdfParams::Scrypt { log_n: 10, r: 8, p: 1 };
    let d = params.to_derive();
    assert_eq!(d.id(), KdfId::Scrypt);
    // Verify it can actually derive
    let result = d.derive(b"test", b"salt1234567890123456789012345678");
    assert!(result.is_ok());
}

#[test]
fn kdf_params_to_derive_argon2id() {
    let params = KdfParams::Argon2id { memory_kib: 1024, iterations: 1, parallelism: 1 };
    let d = params.to_derive();
    assert_eq!(d.id(), KdfId::Argon2id);
    let result = d.derive(b"test", b"salt5678901234567890123456789012");
    assert!(result.is_ok());
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test key::derive::tests --lib`
Expected: FAIL (KdfParams not defined)

**Step 3: Implement KdfParams**

Add to `src/key/derive.rs` after KdfId:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfParams {
    Scrypt { log_n: u8, r: u32, p: u32 },
    Argon2id { memory_kib: u32, iterations: u32, parallelism: u32 },
}

impl KdfParams {
    pub fn id(&self) -> KdfId {
        match self {
            KdfParams::Scrypt { .. } => KdfId::Scrypt,
            KdfParams::Argon2id { .. } => KdfId::Argon2id,
        }
    }

    pub fn to_derive(&self) -> Box<dyn Derive> {
        match self {
            KdfParams::Scrypt { log_n, r, p } => {
                Box::new(ScryptDerive { log_n: *log_n, r: *r, p: *p })
            }
            KdfParams::Argon2id { memory_kib, iterations, parallelism } => {
                Box::new(Argon2idDerive {
                    memory_kib: *memory_kib,
                    iterations: *iterations,
                    parallelism: *parallelism,
                })
            }
        }
    }

    /// Serialize native params: [id:1][params...]
    /// Scrypt:   id(1) + log_n(1) + r(4 LE) + p(4 LE) = 10 bytes
    /// Argon2id: id(1) + memory_kib(4 LE) + iterations(4 LE) + parallelism(4 LE) = 13 bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            KdfParams::Scrypt { log_n, r, p } => {
                out.push(KdfId::Scrypt as u8);
                out.push(*log_n);
                out.extend_from_slice(&r.to_le_bytes());
                out.extend_from_slice(&p.to_le_bytes());
            }
            KdfParams::Argon2id { memory_kib, iterations, parallelism } => {
                out.push(KdfId::Argon2id as u8);
                out.extend_from_slice(&memory_kib.to_le_bytes());
                out.extend_from_slice(&iterations.to_le_bytes());
                out.extend_from_slice(&parallelism.to_le_bytes());
            }
        }
        out
    }

    /// Deserialize from bytes, returns (params, bytes_consumed)
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(Error::Format("empty KDF params".into()));
        }
        let id = KdfId::try_from(data[0])?;
        match id {
            KdfId::Scrypt => {
                if data.len() < 10 {
                    return Err(Error::Format("truncated scrypt params".into()));
                }
                let log_n = data[1];
                let r = u32::from_le_bytes(data[2..6].try_into().unwrap());
                let p = u32::from_le_bytes(data[6..10].try_into().unwrap());
                Ok((KdfParams::Scrypt { log_n, r, p }, 10))
            }
            KdfId::Argon2id => {
                if data.len() < 13 {
                    return Err(Error::Format("truncated argon2id params".into()));
                }
                let memory_kib = u32::from_le_bytes(data[1..5].try_into().unwrap());
                let iterations = u32::from_le_bytes(data[5..9].try_into().unwrap());
                let parallelism = u32::from_le_bytes(data[9..13].try_into().unwrap());
                Ok((KdfParams::Argon2id { memory_kib, iterations, parallelism }, 13))
            }
        }
    }

    /// Human-readable memory description for display
    pub fn memory_display(&self) -> String {
        match self {
            KdfParams::Scrypt { log_n, r, .. } => {
                let bytes = (1u64 << *log_n as u64) * (*r as u64) * 128;
                format!("{}MB", bytes / (1024 * 1024))
            }
            KdfParams::Argon2id { memory_kib, .. } => {
                format!("{}MB", memory_kib / 1024)
            }
        }
    }
}
```

**Step 4: Run tests**

Run: `cargo test key::derive::tests --lib`
Expected: PASS

**Step 5: Commit**

```bash
git add src/key/derive.rs
git commit -m "feat: add KdfParams enum with native param serialization"
git push
```

---

### Task 3: Update CipherLayer trait + all implementations to use CipherId

This is a mechanical refactor across multiple files. Every call site that uses `.id()` as `u8` or compares to `0x20`/`0x21`/`0x22` gets updated.

**Files:**
- Modify: `src/cipher/mod.rs:10` (trait definition)
- Modify: `src/cipher/twofish.rs:13` (impl)
- Modify: `src/cipher/aes.rs:13` (impl)
- Modify: `src/cipher/xchacha.rs:11` (impl)
- Modify: `src/cipher/lookup.rs:7-14` (cipher_by_id)
- Modify: `src/pipeline/envelope.rs:9,19,33,70` (LayerEnvelope)
- Modify: `src/pipeline/mod.rs:34,55,58,99` (Pipeline)

**Step 1: Update CipherLayer trait**

In `src/cipher/mod.rs`, change line 10:

```rust
// Old:
fn id(&self) -> u8;

// New:
fn id(&self) -> CipherId;
```

**Step 2: Update cipher implementations**

In `src/cipher/twofish.rs`:
- Add `use crate::cipher::CipherId;` to imports
- Change line 13: `fn id(&self) -> CipherId { CipherId::Twofish }`
- Update test `twofish_metadata`: `assert_eq!(c.id(), CipherId::Twofish);`

In `src/cipher/aes.rs`:
- Add `use crate::cipher::CipherId;` to imports
- Change line 13: `fn id(&self) -> CipherId { CipherId::Aes }`
- Update test `aes_metadata`: `assert_eq!(c.id(), CipherId::Aes);`

In `src/cipher/xchacha.rs`:
- Add `use crate::cipher::CipherId;` to imports
- Change line 11: `fn id(&self) -> CipherId { CipherId::XChaCha }`
- Update test `xchacha_metadata`: `assert_eq!(c.id(), CipherId::XChaCha);`

**Step 3: Update cipher_by_id**

In `src/cipher/lookup.rs`, change function signature and body:

```rust
use crate::cipher::{CipherLayer, CipherId};
use crate::cipher::twofish::TwofishCtr;
use crate::cipher::aes::AesCtr;
use crate::cipher::xchacha::XChaCha;

pub fn cipher_by_id(id: CipherId) -> Box<dyn CipherLayer> {
    match id {
        CipherId::Twofish => Box::new(TwofishCtr),
        CipherId::Aes => Box::new(AesCtr),
        CipherId::XChaCha => Box::new(XChaCha),
    }
}
```

Note: no `Result` return needed, no wildcard. The function is infallible.

Update lookup tests:

```rust
#[test]
fn lookup_twofish() {
    let c = cipher_by_id(CipherId::Twofish);
    assert_eq!(c.id(), CipherId::Twofish);
}

#[test]
fn lookup_aes() {
    let c = cipher_by_id(CipherId::Aes);
    assert_eq!(c.id(), CipherId::Aes);
}

#[test]
fn lookup_xchacha() {
    let c = cipher_by_id(CipherId::XChaCha);
    assert_eq!(c.id(), CipherId::XChaCha);
}
```

Remove the `lookup_unknown_fails` test (no longer possible to pass unknown ID).

**Step 4: Update LayerEnvelope**

In `src/pipeline/envelope.rs`:

Change `layer_id: u8` to `layer_id: CipherId` in the struct (line 9).

Update `serialize` (line 19): `out.push(self.layer_id as u8);`

Update `deserialize` (line 33): `let layer_id = CipherId::try_from(data[0])?;`

Update `compute_mac` signature (line 70): `layer_id: CipherId` parameter, body: `mac.update(&[layer_id as u8]);`

Update all envelope tests to use `CipherId::Twofish` etc instead of `0x20` etc:
- `envelope_round_trip`: `layer_id: CipherId::Twofish`, `LayerEnvelope::compute_mac(&mac_key, CipherId::Twofish, ...)`
- `envelope_mac_verification_passes`: `CipherId::XChaCha` instead of `0x22`
- `envelope_tampered_payload_fails_mac`: `CipherId::Aes` instead of `0x21`
- `envelope_wrong_key_fails_mac`: `CipherId::Twofish` instead of `0x20`

Add import: `use crate::cipher::CipherId;`

**Step 5: Update Pipeline**

In `src/pipeline/mod.rs`:

Update `layer_descriptors` (line 34): `id: l.id()` stays the same (now returns CipherId, which matches updated LayerDescriptor).

Update `seal` (lines 55,58): `layer.id()` now returns CipherId, which is what LayerEnvelope and compute_mac expect.

Update `validate_no_duplicate_ids` (line 99): `HashSet` already works since CipherId derives Hash+Eq. The format string `0x{:02x}` needs to change to `{:?}` or use `id as u8`.

Update pipeline tests:
- `pipeline_descriptors`: `assert_eq!(descs[0].id, CipherId::Twofish);` etc
- `pipeline_build_from_header`: `assert_eq!(rebuilt.layers[0].id(), CipherId::Twofish);` etc
- `pipeline_duplicate_layer_ids_rejected`: `LayerDescriptor { id: CipherId::Twofish, nonce_size: 16 }` for both entries

**Step 6: Run all tests**

Run: `cargo test`
Expected: PASS

**Step 7: Commit**

```bash
git add src/cipher/ src/pipeline/
git commit -m "refactor: CipherLayer::id() returns CipherId enum, remove wildcard matches"
git push
```

---

### Task 4: Update Derive trait + implementations to use KdfId

**Files:**
- Modify: `src/key/derive.rs:9,32,63` (trait + impls)

**Step 1: Update Derive trait**

Change line 9: `fn id(&self) -> KdfId;`

**Step 2: Update implementations**

ScryptDerive (line 32): `fn id(&self) -> KdfId { KdfId::Scrypt }`

Argon2idDerive (line 63): `fn id(&self) -> KdfId { KdfId::Argon2id }`

**Step 3: Update existing tests**

- `scrypt_metadata`: `assert_eq!(kdf.id(), KdfId::Scrypt);`
- `argon2id_metadata`: `assert_eq!(kdf.id(), KdfId::Argon2id);`
- `kdf_lookup` test: remove entirely (kdf_by_id will be removed in a later task)

**Step 4: Update chain_derive**

In `chain_derive` (line 87), the HKDF label uses `kdf.id()`. Now it returns `KdfId`, so change:

```rust
let label = format!("tomb-kdf-{:02x}-salt", kdf.id() as u8);
```

**Step 5: Update kdf_by_id temporarily**

For now, update `kdf_by_id` to use KdfId internally but still accept u8 (it will be removed in Task 7):

```rust
pub fn kdf_by_id(id: u8) -> Result<Box<dyn Derive>> {
    let kdf_id = KdfId::try_from(id)?;
    match kdf_id {
        KdfId::Scrypt => Ok(Box::new(ScryptDerive::production())),
        KdfId::Argon2id => Ok(Box::new(Argon2idDerive::production())),
    }
}
```

**Step 6: Run tests**

Run: `cargo test --lib`
Expected: PASS

**Step 7: Commit**

```bash
git add src/key/derive.rs
git commit -m "refactor: Derive::id() returns KdfId enum"
git push
```

---

### Task 5: Update PublicHeader format

**Files:**
- Modify: `src/format/header.rs` (KdfDescriptor -> KdfParams, LayerDescriptor.id -> CipherId, version constants)

**Step 1: Update types and imports**

Replace `KdfDescriptor` with import of `KdfParams`:

```rust
use crate::{Error, Result};
use crate::cipher::CipherId;
use crate::key::derive::KdfParams;
```

Remove the `KdfDescriptor` struct entirely.

Update `LayerDescriptor`:

```rust
pub struct LayerDescriptor {
    pub id: CipherId,
    pub nonce_size: u8,
}
```

Add version constants:

```rust
pub const FORMAT_VERSION_MAJOR: u8 = 1;
pub const FORMAT_VERSION_MINOR: u8 = 0;
```

Update `PublicHeader`:

```rust
pub struct PublicHeader {
    pub version_major: u8,
    pub version_minor: u8,
    pub kdf_chain: Vec<KdfParams>,
    pub layers: Vec<LayerDescriptor>,
    pub salt: Vec<u8>,
    pub commitment: Vec<u8>,
}
```

**Step 2: Update serialize**

```rust
pub fn serialize(&self) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(b"TOMB\n");
    out.push(self.version_major);
    out.push(self.version_minor);

    out.push(self.kdf_chain.len() as u8);
    for kdf in &self.kdf_chain {
        out.extend_from_slice(&kdf.serialize());
    }

    out.push(self.layers.len() as u8);
    for layer in &self.layers {
        out.push(layer.id as u8);
        out.push(layer.nonce_size);
    }

    out.extend_from_slice(&self.salt);
    out.extend_from_slice(&self.commitment);

    let total_len = (out.len() + 4) as u32;
    out.extend_from_slice(&total_len.to_le_bytes());

    out
}
```

**Step 3: Update deserialize**

```rust
pub fn deserialize(data: &[u8]) -> Result<(Self, usize)> {
    if data.len() < 5 || &data[..5] != b"TOMB\n" {
        return Err(Error::Format("missing TOMB magic".into()));
    }

    let mut pos = 5;

    if pos + 2 > data.len() { return Err(Error::Format("truncated version".into())); }
    let version_major = data[pos];
    let version_minor = data[pos + 1];
    pos += 2;

    if pos >= data.len() { return Err(Error::Format("truncated kdf count".into())); }
    let kdf_count = data[pos] as usize;
    pos += 1;

    let mut kdf_chain = Vec::with_capacity(kdf_count);
    for _ in 0..kdf_count {
        if pos >= data.len() { return Err(Error::Format("truncated kdf params".into())); }
        let (params, consumed) = KdfParams::deserialize(&data[pos..])?;
        pos += consumed;
        kdf_chain.push(params);
    }

    if pos >= data.len() { return Err(Error::Format("truncated layer count".into())); }
    let layer_count = data[pos] as usize;
    pos += 1;

    let mut layers = Vec::with_capacity(layer_count);
    for _ in 0..layer_count {
        if pos + 2 > data.len() { return Err(Error::Format("truncated layer".into())); }
        let id = CipherId::try_from(data[pos])?;
        let nonce_size = data[pos + 1];
        pos += 2;
        layers.push(LayerDescriptor { id, nonce_size });
    }

    let salt_end = pos.checked_add(32)
        .ok_or_else(|| Error::Format("salt offset overflow".into()))?;
    let commitment_end = salt_end.checked_add(32)
        .ok_or_else(|| Error::Format("commitment offset overflow".into()))?;
    if commitment_end > data.len() { return Err(Error::Format("truncated salt/commitment".into())); }
    let salt = data[pos..salt_end].to_vec();
    let commitment = data[salt_end..commitment_end].to_vec();
    pos = commitment_end;

    let header_len_end = pos.checked_add(4)
        .ok_or_else(|| Error::Format("header length offset overflow".into()))?;
    if header_len_end > data.len() { return Err(Error::Format("truncated header length".into())); }
    let header_len = u32::from_le_bytes(data[pos..header_len_end].try_into().unwrap()) as usize;
    pos = header_len_end;

    if pos != header_len {
        return Err(Error::Format(format!("header length mismatch: expected {header_len}, got {pos}")));
    }

    Ok((Self { version_major, version_minor, kdf_chain, layers, salt, commitment }, pos))
}
```

**Step 4: Update header tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_header_round_trip() {
        let header = PublicHeader {
            version_major: FORMAT_VERSION_MAJOR,
            version_minor: FORMAT_VERSION_MINOR,
            kdf_chain: vec![
                KdfParams::Scrypt { log_n: 20, r: 8, p: 1 },
                KdfParams::Argon2id { memory_kib: 1_048_576, iterations: 4, parallelism: 4 },
            ],
            layers: vec![
                LayerDescriptor { id: CipherId::Twofish, nonce_size: 16 },
                LayerDescriptor { id: CipherId::Aes, nonce_size: 16 },
                LayerDescriptor { id: CipherId::XChaCha, nonce_size: 24 },
            ],
            salt: vec![0xAA; 32],
            commitment: vec![0xBB; 32],
        };

        let bytes = header.serialize();
        assert_eq!(&bytes[..5], b"TOMB\n");

        let (parsed, consumed) = PublicHeader::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.version_major, FORMAT_VERSION_MAJOR);
        assert_eq!(parsed.version_minor, FORMAT_VERSION_MINOR);
        assert_eq!(parsed.kdf_chain.len(), 2);
        assert_eq!(parsed.kdf_chain[0].id(), KdfId::Scrypt);
        assert_eq!(parsed.kdf_chain[1].id(), KdfId::Argon2id);
        assert_eq!(parsed.layers.len(), 3);
        assert_eq!(parsed.layers[0].id, CipherId::Twofish);
        assert_eq!(parsed.salt.len(), 32);
        assert_eq!(parsed.commitment.len(), 32);
    }

    #[test]
    fn public_header_magic_bytes() {
        let header = PublicHeader {
            version_major: FORMAT_VERSION_MAJOR,
            version_minor: FORMAT_VERSION_MINOR,
            kdf_chain: vec![],
            layers: vec![],
            salt: vec![0; 32],
            commitment: vec![0; 32],
        };
        let bytes = header.serialize();
        assert_eq!(&bytes[..5], b"TOMB\n");
    }
}
```

**Step 5: Update format/mod.rs re-exports**

In `src/format/mod.rs` (or wherever the module is declared), make sure `KdfDescriptor` is no longer re-exported. Re-export `FORMAT_VERSION_MAJOR`, `FORMAT_VERSION_MINOR` from header.

**Step 6: Run tests**

Run: `cargo test`
Expected: May fail in lib.rs and pipeline tests that still reference KdfDescriptor and old IDs. Fix those in subsequent tasks. Run just header tests first:

Run: `cargo test format::header --lib`
Expected: PASS

**Step 7: Commit**

```bash
git add src/format/
git commit -m "refactor: header uses KdfParams and CipherId, add version constants"
git push
```

---

### Task 6: Add SealConfig + refactor lib.rs seal/derive_keys

**Files:**
- Modify: `src/lib.rs` (add SealConfig, refactor seal, derive_keys, remove _with_params)

**Step 1: Add SealConfig**

Add to `src/lib.rs` in the public types section:

```rust
use crate::key::derive::{KdfParams, KdfId};
use crate::cipher::CipherId;

pub struct SealConfig {
    pub kdf_chain: Vec<KdfParams>,
    pub cipher_ids: Vec<CipherId>,
}

impl SealConfig {
    pub fn production() -> Self {
        Self {
            kdf_chain: vec![
                KdfParams::Scrypt { log_n: 20, r: 8, p: 1 },
                KdfParams::Argon2id { memory_kib: 1_048_576, iterations: 4, parallelism: 4 },
            ],
            cipher_ids: vec![CipherId::Twofish, CipherId::Aes, CipherId::XChaCha],
        }
    }

    pub fn test() -> Self {
        Self {
            kdf_chain: vec![
                KdfParams::Scrypt { log_n: 10, r: 8, p: 1 },
                KdfParams::Argon2id { memory_kib: 1024, iterations: 1, parallelism: 1 },
            ],
            cipher_ids: vec![CipherId::Twofish, CipherId::Aes, CipherId::XChaCha],
        }
    }
}
```

**Step 2: Refactor derive_keys**

Replace `derive_keys`, `derive_keys_with_params`, and `derive_keys_internal` with a single function:

```rust
pub fn derive_keys(
    passphrase: &Passphrase,
    pipeline: &Pipeline,
    kdf_chain: &[KdfParams],
) -> Result<DerivedKeys> {
    let salt = random_bytes(32);

    let kdfs: Vec<Box<dyn Derive>> = kdf_chain.iter()
        .map(|p| p.to_derive())
        .collect();
    let master = chain_derive(&kdfs, passphrase.as_bytes(), &salt)?;

    let layer_info = pipeline.layer_info();
    let states = expand_layer_keys(&master, &layer_info)?;
    let commitment = compute_commitment(&master);

    Ok(DerivedKeys { master, states, commitment, salt })
}
```

Remove `derive_keys_with_params` and `derive_keys_internal`.

**Step 3: Refactor seal**

Replace both `seal` and `seal_with_params` with a single function:

```rust
pub fn seal(
    input_path: &Path,
    output_path: &Path,
    passphrase: &Passphrase,
    note: Option<&str>,
    config: &SealConfig,
) -> Result<()> {
    let mut prepared = prepare_payload(input_path, note)?;
    let pipeline = Pipeline::from_cipher_ids(&config.cipher_ids)?;
    let keys = derive_keys(passphrase, &pipeline, &config.kdf_chain)?;

    let header = format::PublicHeader {
        version_major: format::FORMAT_VERSION_MAJOR,
        version_minor: format::FORMAT_VERSION_MINOR,
        kdf_chain: config.kdf_chain.clone(),
        layers: pipeline.layer_descriptors(),
        salt: keys.salt.clone(),
        commitment: keys.commitment.as_bytes().to_vec(),
    };

    encrypt_and_write(output_path, &header, &pipeline, &keys.states, &prepared.padded)?;
    prepared.padded.zeroize();
    verify_sealed(output_path, passphrase, &prepared.checksum)?;

    Ok(())
}
```

Remove old `seal` and `seal_with_params`.

**Step 4: Update verify_sealed**

```rust
pub fn verify_sealed(
    output_path: &Path,
    passphrase: &Passphrase,
    expected_checksum: &[u8; 64],
) -> Result<()> {
    let opened = open_file(output_path, passphrase)?;
    let checksum: [u8; 64] = Sha512::digest(&opened.data).into();
    if !bool::from(checksum[..].ct_eq(&expected_checksum[..])) {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}
```

**Step 5: Update lib.rs tests**

```rust
#[test]
fn derive_keys_produces_states() {
    let passphrase = key::Passphrase::new(b"test passphrase words here".to_vec());
    let config = SealConfig::test();
    let pipeline = pipeline::Pipeline::from_cipher_ids(&config.cipher_ids).unwrap();
    let keys = derive_keys(&passphrase, &pipeline, &config.kdf_chain).unwrap();
    assert_eq!(keys.states.len(), 3);
    assert_eq!(keys.salt.len(), 32);
    assert_eq!(keys.commitment.as_bytes().len(), 32);
}

#[test]
fn seal_and_open_round_trip() {
    let dir = std::env::temp_dir().join("tomb_test_roundtrip");
    std::fs::create_dir_all(&dir).unwrap();

    let input = dir.join("secret.txt");
    let output = dir.join("secret.tomb");
    std::fs::write(&input, b"top secret data for tomb test").unwrap();

    let passphrase = key::Passphrase::new(b"test passphrase".to_vec());

    seal(&input, &output, &passphrase, Some("test note"), &SealConfig::test()).unwrap();
    assert!(output.exists());

    let opened = open_file(&output, &passphrase).unwrap();
    assert_eq!(opened.data, b"top secret data for tomb test");
    assert_eq!(opened.filename, "secret.txt");

    std::fs::remove_dir_all(&dir).ok();
}
```

**Step 6: Clean up imports**

Remove unused imports: `ScryptDerive`, `Argon2idDerive` from lib.rs imports (they're now accessed through KdfParams::to_derive).

Update the import line to:

```rust
use crate::key::derive::{Derive, KdfParams, chain_derive};
```

**Step 7: Run tests**

Run: `cargo test --lib`
Expected: PASS

**Step 8: Commit**

```bash
git add src/lib.rs
git commit -m "refactor: seal() takes SealConfig, remove _with_params variants"
git push
```

---

### Task 7: Refactor open_file to be header-driven

**Files:**
- Modify: `src/lib.rs` (open_file reads KDF params from header)

**Step 1: Rewrite open_file**

Replace both `open_file` and `open_file_with_params` with:

```rust
pub fn open_file(
    file_path: &Path,
    passphrase: &Passphrase,
) -> Result<OpenedFile> {
    let tomb_data = fs::read(file_path)?;
    let (header, header_len) = format::PublicHeader::deserialize(&tomb_data)?;

    // Reconstruct KDFs from header params
    let kdfs: Vec<Box<dyn Derive>> = header.kdf_chain.iter()
        .map(|p| p.to_derive())
        .collect();
    let master = chain_derive(&kdfs, passphrase.as_bytes(), &header.salt)?;

    // Verify key commitment (constant-time)
    let commitment = compute_commitment(&master);
    let stored = Commitment::from_bytes(header.commitment.as_slice().try_into()
        .map_err(|_| Error::Format("invalid commitment length".into()))?);
    if !commitment.verify(&stored) {
        return Err(Error::DecryptionFailed);
    }

    let pipeline = Pipeline::build_from_header(&header)?;
    let layer_info = pipeline.layer_info();
    let states = expand_layer_keys(&master, &layer_info)?;

    let sealed_body = &tomb_data[header_len..];
    let mut decrypted = pipeline.open(&states, sealed_body)?;

    // Parse inner header
    let (inner, inner_len) = format::InnerHeader::deserialize(&decrypted)?;
    let original_size = inner.original_size as usize;
    let plaintext_end = inner_len.checked_add(original_size)
        .ok_or(Error::DecryptionFailed)?;
    if plaintext_end > decrypted.len() {
        decrypted.zeroize();
        return Err(Error::DecryptionFailed);
    }

    let plaintext_data = decrypted[inner_len..plaintext_end].to_vec();

    // Verify SHA-512 checksum (constant-time)
    let checksum: [u8; 64] = Sha512::digest(&plaintext_data).into();
    if !bool::from(checksum[..].ct_eq(&inner.checksum[..])) {
        decrypted.zeroize();
        return Err(Error::DecryptionFailed);
    }

    decrypted.zeroize();

    Ok(OpenedFile {
        data: plaintext_data,
        filename: inner.filename,
    })
}
```

Remove `open_file_with_params` entirely.

**Step 2: Run tests**

Run: `cargo test --lib`
Expected: PASS

**Step 3: Commit**

```bash
git add src/lib.rs
git commit -m "refactor: open_file reads KDF params from header, remove _with_params"
git push
```

---

### Task 8: Update Pipeline to accept CipherId

**Files:**
- Modify: `src/pipeline/mod.rs` (add from_cipher_ids constructor)

**Step 1: Add from_cipher_ids**

```rust
pub fn from_cipher_ids(ids: &[CipherId]) -> Result<Self> {
    let layers: Vec<Box<dyn CipherLayer>> = ids.iter()
        .map(|id| cipher_by_id(*id))
        .collect();
    validate_no_duplicate_ids(&layers)?;
    Ok(Self { layers })
}
```

Update `build_from_header`:

```rust
pub fn build_from_header(header: &PublicHeader) -> Result<Self> {
    let layers: Vec<Box<dyn CipherLayer>> = header.layers.iter()
        .map(|desc| cipher_by_id(desc.id))
        .collect();
    validate_no_duplicate_ids(&layers)?;
    Ok(Self { layers })
}
```

Note: `cipher_by_id` now takes `CipherId` and is infallible (returns `Box<dyn CipherLayer>` not `Result`), so the `collect::<Result<_>>()` pattern is no longer needed. Just `.collect()`.

**Step 2: Update validate_no_duplicate_ids format string**

```rust
fn validate_no_duplicate_ids(layers: &[Box<dyn CipherLayer>]) -> Result<()> {
    let mut seen = HashSet::new();
    for layer in layers {
        if !seen.insert(layer.id()) {
            return Err(Error::Format(
                format!("duplicate cipher layer: {:?}", layer.id())
            ));
        }
    }
    Ok(())
}
```

**Step 3: Update pipeline tests**

Update `pipeline_build_from_header` test and `pipeline_duplicate_layer_ids_rejected` test to use `CipherId` variants and `KdfParams` in the header construction.

**Step 4: Run tests**

Run: `cargo test pipeline --lib`
Expected: PASS

**Step 5: Commit**

```bash
git add src/pipeline/mod.rs
git commit -m "refactor: Pipeline::from_cipher_ids accepts CipherId enum"
git push
```

---

### Task 9: Update CLI

**Files:**
- Modify: `src/cli.rs`

**Step 1: Update seal command**

Change line 130 from `crate::seal(&file, &output, &passphrase, note.as_deref())?;` to:

```rust
crate::seal(&file, &output, &passphrase, note.as_deref(), &crate::SealConfig::production())?;
```

**Step 2: Update inspect display**

Replace the KDF display match block (lines 163-169) with:

```rust
for kdf in &header.kdf_chain {
    let id = kdf.id();
    println!("  {} (0x{:02x}): {} memory",
        id.name(), id as u8, kdf.memory_display());
}
```

Replace the cipher display match block (lines 173-179) with:

```rust
for layer in &header.layers {
    println!("  {} (0x{:02x}), nonce: {} bytes",
        layer.id.name(), layer.id as u8, layer.nonce_size);
}
```

**Step 3: Run full test suite**

Run: `cargo test`
Expected: PASS (or close, integration tests may need updating next)

**Step 4: Commit**

```bash
git add src/cli.rs
git commit -m "refactor: CLI uses SealConfig::production() and enum display"
git push
```

---

### Task 10: Update integration tests + clean up

**Files:**
- Modify: `tests/integration.rs`
- Modify: `src/key/derive.rs` (remove kdf_by_id)

**Step 1: Update integration tests**

Replace all `tomb::seal_with_params(...)` with `tomb::seal(..., &tomb::SealConfig::test())`.

Replace all `tomb::open_file_with_params(...)` with `tomb::open_file(...)`.

Remove all `ScryptDerive::test()` and `Argon2idDerive::test()` from test code.

Full updated `tests/integration.rs`:

```rust
use std::path::PathBuf;
use tomb::key::Passphrase;

fn test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tomb_integration_{}_{}", name, std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn full_seal_open_cycle() {
    let dir = test_dir("seal_open");
    let input = dir.join("secret.json");
    let output = dir.join("backup.tomb");

    let content = b"{\"key\": \"value\", \"secret\": 42}";
    std::fs::write(&input, content).unwrap();

    let passphrase = Passphrase::new(b"test passphrase for integration".to_vec());

    tomb::seal(&input, &output, &passphrase, Some("integration test"), &tomb::SealConfig::test()).unwrap();
    assert!(output.exists());

    let opened = tomb::open_file(&output, &passphrase).unwrap();

    assert_eq!(opened.data, content);
    assert_eq!(opened.filename, "secret.json");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn wrong_passphrase_fails() {
    let dir = test_dir("wrong_pass");
    let input = dir.join("data.bin");
    let output = dir.join("data.tomb");

    std::fs::write(&input, b"secret data").unwrap();

    let passphrase = Passphrase::new(b"correct passphrase".to_vec());
    tomb::seal(&input, &output, &passphrase, None, &tomb::SealConfig::test()).unwrap();

    let wrong = Passphrase::new(b"wrong passphrase".to_vec());
    let result = tomb::open_file(&output, &wrong);
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inspect_without_passphrase() {
    let dir = test_dir("inspect");
    let input = dir.join("file.txt");
    let output = dir.join("file.tomb");

    std::fs::write(&input, b"hello").unwrap();
    let passphrase = Passphrase::new(b"test".to_vec());
    tomb::seal(&input, &output, &passphrase, None, &tomb::SealConfig::test()).unwrap();

    let header = tomb::inspect_file(&output).unwrap();
    assert_eq!(header.version_major, 1);
    assert_eq!(header.kdf_chain.len(), 2);
    assert_eq!(header.layers.len(), 3);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn tampered_file_fails() {
    let dir = test_dir("tampered");
    let input = dir.join("data.txt");
    let output = dir.join("data.tomb");

    std::fs::write(&input, b"important data").unwrap();
    let passphrase = Passphrase::new(b"test passphrase".to_vec());
    tomb::seal(&input, &output, &passphrase, None, &tomb::SealConfig::test()).unwrap();

    let mut data = std::fs::read(&output).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    std::fs::write(&output, &data).unwrap();

    let result = tomb::open_file(&output, &passphrase);
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn large_file_round_trip() {
    let dir = test_dir("large");
    let input = dir.join("large.bin");
    let output = dir.join("large.tomb");

    let content: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    std::fs::write(&input, &content).unwrap();

    let passphrase = Passphrase::new(b"large file test".to_vec());
    tomb::seal(&input, &output, &passphrase, None, &tomb::SealConfig::test()).unwrap();

    let opened = tomb::open_file(&output, &passphrase).unwrap();

    assert_eq!(opened.data, content);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn empty_file_round_trip() {
    let dir = test_dir("empty");
    let input = dir.join("empty.bin");
    let output = dir.join("empty.tomb");

    std::fs::write(&input, b"").unwrap();

    let passphrase = Passphrase::new(b"empty file test".to_vec());
    tomb::seal(&input, &output, &passphrase, None, &tomb::SealConfig::test()).unwrap();

    let opened = tomb::open_file(&output, &passphrase).unwrap();

    assert!(opened.data.is_empty());
    assert_eq!(opened.filename, "empty.bin");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn note_preserved() {
    let dir = test_dir("note");
    let input = dir.join("noted.txt");
    let output = dir.join("noted.tomb");

    std::fs::write(&input, b"data with a note").unwrap();

    let passphrase = Passphrase::new(b"note test passphrase".to_vec());
    let note_text = "this is my important note about the backup";
    tomb::seal(&input, &output, &passphrase, Some(note_text), &tomb::SealConfig::test()).unwrap();

    let opened = tomb::open_file(&output, &passphrase).unwrap();

    assert_eq!(opened.data, b"data with a note");
    assert_eq!(opened.filename, "noted.txt");

    std::fs::remove_dir_all(&dir).ok();
}
```

**Step 2: Remove kdf_by_id from derive.rs**

Delete the `kdf_by_id` function entirely from `src/key/derive.rs`. Also remove its test (`kdf_lookup`).

**Step 3: Remove ScryptDerive/Argon2idDerive production() and test()**

These convenience methods are replaced by `SealConfig::production()` and `SealConfig::test()`. However, `production()` and `test()` are still useful for the structs themselves if someone constructs them manually. Keep them for now, they do no harm.

Actually, check if they're used anywhere after the refactor. If not, remove them.

**Step 4: Run full test suite**

Run: `cargo test`
Expected: ALL PASS

**Step 5: Run clippy and fmt**

Run: `cargo clippy` and `cargo fmt --check`
Expected: No warnings, no formatting issues

**Step 6: Commit**

```bash
git add src/key/derive.rs tests/integration.rs
git commit -m "refactor: update integration tests, remove kdf_by_id"
git push
```

---

## Summary of changes by file

| File | Changes |
|------|---------|
| `src/cipher/mod.rs` | Add `CipherId` enum, `CipherLayer::id()` returns `CipherId` |
| `src/cipher/twofish.rs` | `id()` returns `CipherId::Twofish` |
| `src/cipher/aes.rs` | `id()` returns `CipherId::Aes` |
| `src/cipher/xchacha.rs` | `id()` returns `CipherId::XChaCha` |
| `src/cipher/lookup.rs` | `cipher_by_id(CipherId)` infallible, no wildcard |
| `src/key/derive.rs` | Add `KdfId`, `KdfParams` enums, `Derive::id()` returns `KdfId`, remove `kdf_by_id` |
| `src/format/header.rs` | Remove `KdfDescriptor`, use `KdfParams` + `CipherId`, add version constants |
| `src/pipeline/mod.rs` | Add `from_cipher_ids`, update to use `CipherId` |
| `src/pipeline/envelope.rs` | `layer_id: CipherId`, serialize as `u8` |
| `src/lib.rs` | Add `SealConfig`, single `seal()`, header-driven `open_file()`, remove `_with_params` |
| `src/cli.rs` | Use `SealConfig::production()`, enum display in inspect |
| `tests/integration.rs` | Use `SealConfig::test()` + `open_file()` everywhere |
