# tomb Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a multi-layer encryption CLI tool that makes brute force mathematically impossible.

**Architecture:** Rust binary with library/CLI separation. Three cipher layers (Twofish-CTR, AES-CTR, XChaCha20), each with HMAC-SHA256 authentication. Chained KDF (scrypt -> Argon2id). 21-word EFF diceware passphrase. Binary .tomb file format with public header and per-layer envelopes.

**Tech Stack:** Rust, RustCrypto ecosystem (aes, twofish, chacha20, scrypt, argon2, hkdf, hmac, sha2), clap for CLI, zeroize for memory safety.

---

## Dependency Graph

```
Phase 1: Foundation (sequential)
  T1: Project scaffold
  T2: Error + Result types
  T3: Key types (MasterKey, LayerKey, Passphrase, Commitment)

Phase 2: Core Modules (4 parallel streams)
  Stream A: Ciphers          Stream B: KDF + Key Ops     Stream C: Format           Stream D: Passphrase
  T4: Trait + Twofish        T8: Trait + Scrypt          T13: PADME padding         T17: EFF wordlist
  T5: AES-CTR                T9: Argon2id                T14: InnerHeader           T18: Validation
  T6: XChaCha20              T10: chain_derive           T15: PublicHeader          T19: Generation
  T7: cipher_by_id           T11: HKDF expand            T16: LayerEnvelope
                              T12: HMAC commit

Phase 3: Pipeline (sequential, needs Streams A + C)
  T20: LayerState + Pipeline seal
  T21: Pipeline open + build_from_header

Phase 4: Library API (sequential, needs Phase 2 + 3)
  T22: prepare_payload
  T23: derive_keys
  T24: encrypt_and_write + verify_sealed
  T25: seal + open orchestrators

Phase 5: CLI (sequential, needs Phase 4 + Stream D)
  T26: Clap structure + inspect command
  T27: Passphrase prompts + generate command
  T28: seal + open + verify commands

Phase 6: Polish
  T29: FORMAT.md
  T30: Integration tests
  T31: Vendor deps + build config
```

## Agent Team Strategy

**Phase 1:** Single agent sets up project foundation. Must complete before Phase 2.

**Phase 2:** 4 parallel agents, one per stream:
- **Agent A (Ciphers):** Tasks 4-7. Implements CipherLayer trait and all 3 cipher implementations.
- **Agent B (KDF):** Tasks 8-12. Implements Derive trait, both KDFs, chaining, HKDF expansion, HMAC commitment.
- **Agent C (Format):** Tasks 13-16. Implements PADME, headers, and layer envelope.
- **Agent D (Passphrase):** Tasks 17-19. Embeds EFF wordlist, validation, generation.

**Phase 3-6:** Sequential. Single agent or coordinator.

---

## Phase 1: Foundation

### Task 1: Project Scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `src/lib.rs`
- Create: `src/cli.rs` (empty stub)
- Create: `src/key/mod.rs` (empty)
- Create: `src/key/derive.rs` (empty)
- Create: `src/key/expand.rs` (empty)
- Create: `src/key/commit.rs` (empty)
- Create: `src/cipher/mod.rs` (empty)
- Create: `src/cipher/twofish.rs` (empty)
- Create: `src/cipher/aes.rs` (empty)
- Create: `src/cipher/xchacha.rs` (empty)
- Create: `src/cipher/lookup.rs` (empty)
- Create: `src/pipeline/mod.rs` (empty)
- Create: `src/pipeline/envelope.rs` (empty)
- Create: `src/format/mod.rs` (empty)
- Create: `src/format/header.rs` (empty)
- Create: `src/format/inner.rs` (empty)
- Create: `src/format/padding.rs` (empty)
- Create: `src/passphrase/mod.rs` (empty)
- Create: `src/passphrase/generate.rs` (empty)
- Create: `src/passphrase/wordlist.rs` (empty)

**Step 1: Create project**

```bash
cd /Users/calum/code/github.com/0x63616c/tomb
cargo init .
```

**Step 2: Write Cargo.toml**

```toml
[package]
name = "tomb"
version = "0.1.0"
edition = "2021"
description = "Encrypt anything with a passphrase. Recover it decades later."

[dependencies]
# Cipher layers (CTR mode for all)
aes = "0.8"
ctr = "0.9"
twofish = "0.7"
chacha20 = "0.9"

# Key derivation chain
scrypt = "0.11"
argon2 = "0.5"

# Key expansion + per-layer auth + commitment
hkdf = "0.12"
sha2 = "0.10"
hmac = "0.12"

# Memory safety + constant time
zeroize = { version = "1", features = ["derive"] }
subtle = "2"

# CLI
clap = { version = "4", features = ["derive"] }

# Randomness
rand = "0.8"

# Passphrase entry (no echo)
rpassword = "7"

[profile.release]
strip = true
lto = true
```

**Step 3: Create directory structure and empty module files**

Create all directories: `src/key/`, `src/cipher/`, `src/pipeline/`, `src/format/`, `src/passphrase/`

Each empty module file gets just a comment placeholder.

**Step 4: Write src/main.rs**

```rust
fn main() {
    if let Err(e) = tomb::cli::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
```

**Step 5: Write src/lib.rs with module declarations and utility**

```rust
pub mod key;
pub mod cipher;
pub mod pipeline;
pub mod format;
pub mod passphrase;
pub mod cli;

use rand::rngs::OsRng;
use rand::RngCore;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
```

**Step 6: Write src/cli.rs stub**

```rust
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("tomb v{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
```

**Step 7: Write all empty mod.rs files** so module declarations compile.

Each `mod.rs` should declare its submodules. For example `src/key/mod.rs`:
```rust
pub mod derive;
pub mod expand;
pub mod commit;
```

Similarly for cipher, pipeline, format, passphrase.

**Step 8: Verify it compiles**

Run: `cargo build`
Expected: Compiles with no errors (warnings OK for now).

**Step 9: Commit**

```bash
git add -A && git commit -m "feat: project scaffold with all module stubs" && git push
```

---

### Task 2: Error and Result Types

**Files:**
- Modify: `src/lib.rs`

**Step 1: Write test**

Add to `src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_decryption_failed() {
        let e = Error::DecryptionFailed;
        assert_eq!(format!("{e}"), "decryption failed");
    }

    #[test]
    fn error_display_unknown_layer() {
        let e = Error::UnknownLayer(0xFF);
        assert!(format!("{e}").contains("0xff"));
    }

    #[test]
    fn error_display_word_not_in_list() {
        let e = Error::WordNotInList("xyzzy".into());
        assert!(format!("{e}").contains("xyzzy"));
    }
}
```

Run: `cargo test error_display` -- expect FAIL

**Step 2: Implement Error and Result**

Add to `src/lib.rs` (above the modules):

```rust
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    DecryptionFailed,
    Encryption(String),
    KeyExpansion,
    CommitmentMismatch,
    Format(String),
    VerificationFailed,
    PassphraseMismatch,
    PassphraseInvalid(String),
    WordNotInList(String),
    UnknownLayer(u8),
    UnknownKdf(u8),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::Encryption(msg) => write!(f, "encryption error: {msg}"),
            Self::KeyExpansion => write!(f, "key expansion failed"),
            Self::CommitmentMismatch => write!(f, "key commitment mismatch"),
            Self::Format(msg) => write!(f, "format error: {msg}"),
            Self::VerificationFailed => write!(f, "verification failed: sealed file does not match original"),
            Self::PassphraseMismatch => write!(f, "passphrases do not match"),
            Self::PassphraseInvalid(msg) => write!(f, "invalid passphrase: {msg}"),
            Self::WordNotInList(w) => write!(f, "'{w}' is not in the EFF diceware word list"),
            Self::UnknownLayer(id) => write!(f, "unknown layer type 0x{id:02x}, newer version of tomb may be required"),
            Self::UnknownKdf(id) => write!(f, "unknown KDF type 0x{id:02x}, newer version of tomb may be required"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
```

Run: `cargo test error_display` -- expect PASS

**Step 3: Commit**

```bash
git add src/lib.rs && git commit -m "feat: add Error enum and Result type alias" && git push
```

---

### Task 3: Key Types

**Files:**
- Modify: `src/key/mod.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_as_bytes() {
        let key = MasterKey([42u8; 32]);
        assert_eq!(key.as_bytes().len(), 32);
        assert_eq!(key.as_bytes()[0], 42);
    }

    #[test]
    fn layer_key_as_bytes() {
        let key = LayerKey([7u8; 32]);
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn passphrase_as_bytes() {
        let p = Passphrase("hello world".as_bytes().to_vec());
        assert_eq!(p.as_bytes(), b"hello world");
    }

    #[test]
    fn commitment_verify_same() {
        let a = Commitment([1u8; 32]);
        let b = Commitment([1u8; 32]);
        assert!(a.verify(&b));
    }

    #[test]
    fn commitment_verify_different() {
        let a = Commitment([1u8; 32]);
        let b = Commitment([2u8; 32]);
        assert!(!a.verify(&b));
    }
}
```

Run: `cargo test key::tests` -- expect FAIL

**Step 2: Implement**

```rust
pub mod derive;
pub mod expand;
pub mod commit;

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub(crate) [u8; 32]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LayerKey(pub(crate) [u8; 32]);

impl LayerKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Passphrase(pub(crate) Vec<u8>);

impl Passphrase {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Commitment(pub(crate) [u8; 32]);

impl Commitment {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn verify(&self, other: &Commitment) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}
```

Run: `cargo test key::tests` -- expect PASS

**Step 3: Commit**

```bash
git add src/key/mod.rs && git commit -m "feat: add MasterKey, LayerKey, Passphrase, Commitment types" && git push
```

---

## Phase 2: Core Modules (Parallel Streams)

> Phase 2 streams A-D can execute in parallel. Each stream depends only on Phase 1 (Error types + Key types).

---

### Stream A: Ciphers

### Task 4: CipherLayer Trait + TwofishCtr

**Depends on:** T2, T3
**Files:**
- Modify: `src/cipher/mod.rs`
- Modify: `src/cipher/twofish.rs`

**Step 1: Write tests in `src/cipher/twofish.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::LayerKey;

    #[test]
    fn twofish_round_trip() {
        let key = LayerKey([0xAA; 32]);
        let nonce = [0u8; 16];
        let plaintext = b"hello tomb twofish test data!!!!";

        let cipher = TwofishCtr;
        let encrypted = cipher.encrypt(&key, &nonce, plaintext).unwrap();
        assert_ne!(&encrypted, plaintext);

        let decrypted = cipher.decrypt(&key, &nonce, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn twofish_metadata() {
        let c = TwofishCtr;
        assert_eq!(c.id(), 0x20);
        assert_eq!(c.key_size(), 32);
        assert_eq!(c.nonce_size(), 16);
    }
}
```

Run: `cargo test cipher::twofish` -- expect FAIL

**Step 2: Define CipherLayer trait in `src/cipher/mod.rs`**

```rust
pub mod twofish;
pub mod aes;
pub mod xchacha;
pub mod lookup;

use crate::key::LayerKey;
use crate::Result;

pub trait CipherLayer {
    fn id(&self) -> u8;
    fn name(&self) -> &str;
    fn encrypt_label(&self) -> &str;
    fn mac_label(&self) -> &str;
    fn key_size(&self) -> usize;
    fn nonce_size(&self) -> usize;
    fn encrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>>;
}

pub struct LayerDescriptor {
    pub id: u8,
    pub nonce_size: u8,
}
```

**Step 3: Implement TwofishCtr in `src/cipher/twofish.rs`**

```rust
use crate::cipher::CipherLayer;
use crate::key::LayerKey;
use crate::{Error, Result};

use twofish::Twofish;
use ctr::cipher::{KeyIvInit, StreamCipher};

type TwofishCtrMode = ctr::Ctr128BE<Twofish>;

pub struct TwofishCtr;

impl CipherLayer for TwofishCtr {
    fn id(&self) -> u8 { 0x20 }
    fn name(&self) -> &str { "twofish-256-ctr" }
    fn encrypt_label(&self) -> &str { "tomb-twofish-256-ctr" }
    fn mac_label(&self) -> &str { "tomb-twofish-256-ctr-mac" }
    fn key_size(&self) -> usize { 32 }
    fn nonce_size(&self) -> usize { 16 }

    fn encrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = data.to_vec();
        let mut cipher = TwofishCtrMode::new(key.as_bytes().into(), nonce.into());
        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    fn decrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(key, nonce, data) // CTR mode: encrypt == decrypt
    }
}
```

Run: `cargo test cipher::twofish` -- expect PASS

**Step 4: Commit**

```bash
git add src/cipher/ && git commit -m "feat: add CipherLayer trait and TwofishCtr implementation" && git push
```

---

### Task 5: AesCtr

**Depends on:** T4
**Files:**
- Modify: `src/cipher/aes.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::LayerKey;

    #[test]
    fn aes_round_trip() {
        let key = LayerKey([0xBB; 32]);
        let nonce = [0u8; 16];
        let plaintext = b"hello tomb aes test data!!!!1234";

        let cipher = AesCtr;
        let encrypted = cipher.encrypt(&key, &nonce, plaintext).unwrap();
        assert_ne!(&encrypted, plaintext);

        let decrypted = cipher.decrypt(&key, &nonce, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn aes_metadata() {
        let c = AesCtr;
        assert_eq!(c.id(), 0x21);
        assert_eq!(c.key_size(), 32);
        assert_eq!(c.nonce_size(), 16);
    }
}
```

Run: `cargo test cipher::aes` -- expect FAIL

**Step 2: Implement**

```rust
use crate::cipher::CipherLayer;
use crate::key::LayerKey;
use crate::{Error, Result};

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};

type Aes256CtrMode = ctr::Ctr128BE<Aes256>;

pub struct AesCtr;

impl CipherLayer for AesCtr {
    fn id(&self) -> u8 { 0x21 }
    fn name(&self) -> &str { "aes-256-ctr" }
    fn encrypt_label(&self) -> &str { "tomb-aes-256-ctr" }
    fn mac_label(&self) -> &str { "tomb-aes-256-ctr-mac" }
    fn key_size(&self) -> usize { 32 }
    fn nonce_size(&self) -> usize { 16 }

    fn encrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = data.to_vec();
        let mut cipher = Aes256CtrMode::new(key.as_bytes().into(), nonce.into());
        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    fn decrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(key, nonce, data)
    }
}
```

Run: `cargo test cipher::aes` -- expect PASS

**Step 3: Commit**

```bash
git add src/cipher/aes.rs && git commit -m "feat: add AesCtr cipher implementation" && git push
```

---

### Task 6: XChaCha20

**Depends on:** T4
**Files:**
- Modify: `src/cipher/xchacha.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::LayerKey;

    #[test]
    fn xchacha_round_trip() {
        let key = LayerKey([0xCC; 32]);
        let nonce = [0u8; 24]; // XChaCha20 uses 24-byte nonce
        let plaintext = b"hello tomb xchacha test data!!!!";

        let cipher = XChaCha;
        let encrypted = cipher.encrypt(&key, &nonce, plaintext).unwrap();
        assert_ne!(&encrypted, plaintext);

        let decrypted = cipher.decrypt(&key, &nonce, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn xchacha_metadata() {
        let c = XChaCha;
        assert_eq!(c.id(), 0x22);
        assert_eq!(c.key_size(), 32);
        assert_eq!(c.nonce_size(), 24);
    }
}
```

Run: `cargo test cipher::xchacha` -- expect FAIL

**Step 2: Implement**

```rust
use crate::cipher::CipherLayer;
use crate::key::LayerKey;
use crate::{Error, Result};

use chacha20::XChaCha20 as XChaCha20Cipher;
use chacha20::cipher::{KeyIvInit, StreamCipher};

pub struct XChaCha;

impl CipherLayer for XChaCha {
    fn id(&self) -> u8 { 0x22 }
    fn name(&self) -> &str { "xchacha20" }
    fn encrypt_label(&self) -> &str { "tomb-xchacha20" }
    fn mac_label(&self) -> &str { "tomb-xchacha20-mac" }
    fn key_size(&self) -> usize { 32 }
    fn nonce_size(&self) -> usize { 24 }

    fn encrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = data.to_vec();
        let mut cipher = XChaCha20Cipher::new(key.as_bytes().into(), nonce.into());
        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    fn decrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(key, nonce, data)
    }
}
```

Run: `cargo test cipher::xchacha` -- expect PASS

**Step 3: Commit**

```bash
git add src/cipher/xchacha.rs && git commit -m "feat: add XChaCha20 cipher implementation" && git push
```

---

### Task 7: cipher_by_id Lookup

**Depends on:** T4, T5, T6
**Files:**
- Modify: `src/cipher/lookup.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_twofish() {
        let c = cipher_by_id(0x20).unwrap();
        assert_eq!(c.id(), 0x20);
    }

    #[test]
    fn lookup_aes() {
        let c = cipher_by_id(0x21).unwrap();
        assert_eq!(c.id(), 0x21);
    }

    #[test]
    fn lookup_xchacha() {
        let c = cipher_by_id(0x22).unwrap();
        assert_eq!(c.id(), 0x22);
    }

    #[test]
    fn lookup_unknown_fails() {
        assert!(cipher_by_id(0xFF).is_err());
    }
}
```

Run: `cargo test cipher::lookup` -- expect FAIL

**Step 2: Implement**

```rust
use crate::cipher::CipherLayer;
use crate::cipher::twofish::TwofishCtr;
use crate::cipher::aes::AesCtr;
use crate::cipher::xchacha::XChaCha;
use crate::{Error, Result};

pub fn cipher_by_id(id: u8) -> Result<Box<dyn CipherLayer>> {
    match id {
        0x20 => Ok(Box::new(TwofishCtr)),
        0x21 => Ok(Box::new(AesCtr)),
        0x22 => Ok(Box::new(XChaCha)),
        _ => Err(Error::UnknownLayer(id)),
    }
}
```

Run: `cargo test cipher::lookup` -- expect PASS

**Step 3: Commit**

```bash
git add src/cipher/lookup.rs && git commit -m "feat: add cipher_by_id lookup function" && git push
```

---

### Stream B: Key Derivation

### Task 8: Derive Trait + ScryptDerive

**Depends on:** T2, T3
**Files:**
- Modify: `src/key/derive.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrypt_derive_deterministic() {
        let kdf = ScryptDerive::test();
        let key1 = kdf.derive(b"passphrase", b"salt1234567890123456789012345678").unwrap();
        let key2 = kdf.derive(b"passphrase", b"salt1234567890123456789012345678").unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn scrypt_derive_different_input_different_output() {
        let kdf = ScryptDerive::test();
        let key1 = kdf.derive(b"passphrase1", b"salt1234567890123456789012345678").unwrap();
        let key2 = kdf.derive(b"passphrase2", b"salt1234567890123456789012345678").unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn scrypt_metadata() {
        let kdf = ScryptDerive::test();
        assert_eq!(kdf.id(), 0x10);
    }
}
```

Run: `cargo test key::derive` -- expect FAIL

**Step 2: Implement**

```rust
use crate::key::MasterKey;
use crate::{Error, Result};

pub trait Derive {
    fn id(&self) -> u8;
    fn derive(&self, input: &[u8], salt: &[u8]) -> Result<MasterKey>;
}

pub struct ScryptDerive {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

impl ScryptDerive {
    pub fn production() -> Self {
        Self { log_n: 20, r: 8, p: 1 } // 1 GB memory
    }

    pub fn test() -> Self {
        Self { log_n: 10, r: 8, p: 1 } // ~1 MB, fast
    }
}

impl Derive for ScryptDerive {
    fn id(&self) -> u8 { 0x10 }

    fn derive(&self, input: &[u8], salt: &[u8]) -> Result<MasterKey> {
        let params = scrypt::Params::new(self.log_n, self.r, self.p, 32)
            .map_err(|e| Error::Encryption(format!("scrypt params: {e}")))?;
        let mut output = [0u8; 32];
        scrypt::scrypt(input, salt, &params, &mut output)
            .map_err(|e| Error::Encryption(format!("scrypt: {e}")))?;
        Ok(MasterKey(output))
    }
}
```

Run: `cargo test key::derive` -- expect PASS

**Step 3: Commit**

```bash
git add src/key/derive.rs && git commit -m "feat: add Derive trait and ScryptDerive" && git push
```

---

### Task 9: Argon2idDerive

**Depends on:** T8
**Files:**
- Modify: `src/key/derive.rs`

**Step 1: Write tests** (append to existing tests module)

```rust
    #[test]
    fn argon2id_derive_deterministic() {
        let kdf = Argon2idDerive::test();
        let key1 = kdf.derive(b"passphrase", b"salt5678901234567890123456789012").unwrap();
        let key2 = kdf.derive(b"passphrase", b"salt5678901234567890123456789012").unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn argon2id_different_from_scrypt() {
        let salt = b"salt1234567890123456789012345678";
        let s = ScryptDerive::test().derive(b"passphrase", salt).unwrap();
        let a = Argon2idDerive::test().derive(b"passphrase", salt).unwrap();
        assert_ne!(s.as_bytes(), a.as_bytes());
    }

    #[test]
    fn argon2id_metadata() {
        let kdf = Argon2idDerive::test();
        assert_eq!(kdf.id(), 0x11);
    }
```

Run: `cargo test argon2id` -- expect FAIL

**Step 2: Implement** (append to derive.rs)

```rust
use argon2::{Argon2, Algorithm, Version};

pub struct Argon2idDerive {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2idDerive {
    pub fn production() -> Self {
        Self { memory_kib: 1_048_576, iterations: 4, parallelism: 4 } // 1 GB
    }

    pub fn test() -> Self {
        Self { memory_kib: 1024, iterations: 1, parallelism: 1 } // ~1 MB, fast
    }
}

impl Derive for Argon2idDerive {
    fn id(&self) -> u8 { 0x11 }

    fn derive(&self, input: &[u8], salt: &[u8]) -> Result<MasterKey> {
        let params = argon2::Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|e| Error::Encryption(format!("argon2 params: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; 32];
        argon2.hash_password_into(input, salt, &mut output)
            .map_err(|e| Error::Encryption(format!("argon2: {e}")))?;
        Ok(MasterKey(output))
    }
}
```

Run: `cargo test argon2id` -- expect PASS

**Step 3: Commit**

```bash
git add src/key/derive.rs && git commit -m "feat: add Argon2idDerive" && git push
```

---

### Task 10: chain_derive

**Depends on:** T8, T9
**Files:**
- Modify: `src/key/derive.rs`

**Step 1: Write tests**

```rust
    #[test]
    fn chain_derive_deterministic() {
        let kdfs: Vec<Box<dyn Derive>> = vec![
            Box::new(ScryptDerive::test()),
            Box::new(Argon2idDerive::test()),
        ];
        let salt = b"salt1234567890123456789012345678";
        let key1 = chain_derive(&kdfs, b"passphrase", salt).unwrap();
        let key2 = chain_derive(&kdfs, b"passphrase", salt).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn chain_derive_different_from_single_kdf() {
        let salt = b"salt1234567890123456789012345678";
        let single = ScryptDerive::test().derive(b"passphrase", salt).unwrap();
        let kdfs: Vec<Box<dyn Derive>> = vec![
            Box::new(ScryptDerive::test()),
            Box::new(Argon2idDerive::test()),
        ];
        let chained = chain_derive(&kdfs, b"passphrase", salt).unwrap();
        assert_ne!(single.as_bytes(), chained.as_bytes());
    }
```

Run: `cargo test chain_derive` -- expect FAIL

**Step 2: Implement**

```rust
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

pub fn chain_derive(
    kdfs: &[Box<dyn Derive>],
    passphrase: &[u8],
    salt: &[u8],
) -> Result<MasterKey> {
    let prk = Hkdf::<Sha256>::new(None, salt);
    let mut input = passphrase.to_vec();

    for kdf in kdfs {
        let label = format!("tomb-kdf-{:02x}-salt", kdf.id());
        let mut kdf_salt = vec![0u8; 32];
        prk.expand(label.as_bytes(), &mut kdf_salt)
            .map_err(|_| Error::KeyExpansion)?;
        let result = kdf.derive(&input, &kdf_salt)?;
        input.zeroize();
        input = result.as_bytes().to_vec();
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&input);
    input.zeroize();
    Ok(MasterKey(key))
}
```

Run: `cargo test chain_derive` -- expect PASS

**Step 3: Commit**

```bash
git add src/key/derive.rs && git commit -m "feat: add chain_derive for chained KDF" && git push
```

---

### Task 11: HKDF Key Expansion

**Depends on:** T3
**Files:**
- Modify: `src/key/expand.rs`

Note: This function produces per-layer `LayerState` structs. It needs cipher metadata (labels, nonce sizes). To avoid circular deps, it accepts slices of label strings and nonce sizes rather than importing Pipeline directly.

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MasterKey;

    #[test]
    fn expand_produces_correct_count() {
        let master = MasterKey([0xAA; 32]);
        let layer_info = vec![
            LayerInfo { encrypt_label: "tomb-twofish-256-ctr", mac_label: "tomb-twofish-256-ctr-mac", nonce_size: 16 },
            LayerInfo { encrypt_label: "tomb-aes-256-ctr", mac_label: "tomb-aes-256-ctr-mac", nonce_size: 16 },
            LayerInfo { encrypt_label: "tomb-xchacha20", mac_label: "tomb-xchacha20-mac", nonce_size: 24 },
        ];
        let states = expand_layer_keys(&master, &layer_info).unwrap();
        assert_eq!(states.len(), 3);
        assert_eq!(states[0].nonce.len(), 16);
        assert_eq!(states[2].nonce.len(), 24);
    }

    #[test]
    fn expand_different_keys_per_layer() {
        let master = MasterKey([0xBB; 32]);
        let layer_info = vec![
            LayerInfo { encrypt_label: "tomb-twofish-256-ctr", mac_label: "tomb-twofish-256-ctr-mac", nonce_size: 16 },
            LayerInfo { encrypt_label: "tomb-aes-256-ctr", mac_label: "tomb-aes-256-ctr-mac", nonce_size: 16 },
        ];
        let states = expand_layer_keys(&master, &layer_info).unwrap();
        assert_ne!(states[0].encrypt_key.as_bytes(), states[1].encrypt_key.as_bytes());
        assert_ne!(states[0].mac_key.as_bytes(), states[1].mac_key.as_bytes());
    }

    #[test]
    fn expand_encrypt_key_differs_from_mac_key() {
        let master = MasterKey([0xCC; 32]);
        let layer_info = vec![
            LayerInfo { encrypt_label: "tomb-twofish-256-ctr", mac_label: "tomb-twofish-256-ctr-mac", nonce_size: 16 },
        ];
        let states = expand_layer_keys(&master, &layer_info).unwrap();
        assert_ne!(states[0].encrypt_key.as_bytes(), states[0].mac_key.as_bytes());
    }
}
```

Run: `cargo test key::expand` -- expect FAIL

**Step 2: Implement**

```rust
use crate::key::{MasterKey, LayerKey};
use crate::{Error, Result, random_bytes};

use hkdf::Hkdf;
use sha2::Sha256;

pub struct LayerInfo {
    pub encrypt_label: &'static str,
    pub mac_label: &'static str,
    pub nonce_size: usize,
}

pub struct LayerState {
    pub encrypt_key: LayerKey,
    pub mac_key: LayerKey,
    pub nonce: Vec<u8>,
}

pub fn expand_layer_keys(
    master: &MasterKey,
    layers: &[LayerInfo],
) -> Result<Vec<LayerState>> {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut states = Vec::new();

    for layer in layers {
        let mut encrypt_key = [0u8; 32];
        hk.expand(layer.encrypt_label.as_bytes(), &mut encrypt_key)
            .map_err(|_| Error::KeyExpansion)?;

        let mut mac_key = [0u8; 32];
        hk.expand(layer.mac_label.as_bytes(), &mut mac_key)
            .map_err(|_| Error::KeyExpansion)?;

        let nonce = random_bytes(layer.nonce_size);

        states.push(LayerState {
            encrypt_key: LayerKey(encrypt_key),
            mac_key: LayerKey(mac_key),
            nonce,
        });
    }

    Ok(states)
}
```

Run: `cargo test key::expand` -- expect PASS

**Step 3: Commit**

```bash
git add src/key/expand.rs && git commit -m "feat: add HKDF key expansion for per-layer keys" && git push
```

---

### Task 12: HMAC Key Commitment

**Depends on:** T3
**Files:**
- Modify: `src/key/commit.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MasterKey;

    #[test]
    fn commitment_deterministic() {
        let master = MasterKey([0xDD; 32]);
        let c1 = compute_commitment(&master);
        let c2 = compute_commitment(&master);
        assert!(c1.verify(&c2));
    }

    #[test]
    fn commitment_different_keys_different_output() {
        let m1 = MasterKey([0x01; 32]);
        let m2 = MasterKey([0x02; 32]);
        let c1 = compute_commitment(&m1);
        let c2 = compute_commitment(&m2);
        assert!(!c1.verify(&c2));
    }
}
```

Run: `cargo test key::commit` -- expect FAIL

**Step 2: Implement**

```rust
use crate::key::{MasterKey, Commitment};

use hmac::{Hmac, Mac};
use sha2::Sha256;

const COMMITMENT_LABEL: &[u8] = b"tomb-key-commitment";

pub fn compute_commitment(master: &MasterKey) -> Commitment {
    let mut mac = Hmac::<Sha256>::new_from_slice(master.as_bytes())
        .expect("HMAC key size is always valid");
    mac.update(COMMITMENT_LABEL);
    let result = mac.finalize().into_bytes();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Commitment(bytes)
}
```

Run: `cargo test key::commit` -- expect PASS

**Step 3: Commit**

```bash
git add src/key/commit.rs && git commit -m "feat: add HMAC-SHA256 key commitment" && git push
```

---

### Stream C: Format

### Task 13: PADME Padding

**Depends on:** T2
**Files:**
- Modify: `src/format/padding.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padme_small_input_rounds_to_256() {
        assert_eq!(padme_length(1), 256);
        assert_eq!(padme_length(100), 256);
        assert_eq!(padme_length(256), 256);
    }

    #[test]
    fn padme_output_gte_input() {
        for size in [257, 500, 1000, 4096, 65536, 1_000_000] {
            assert!(padme_length(size) >= size, "padme_length({size}) was {}", padme_length(size));
        }
    }

    #[test]
    fn padme_overhead_within_12_percent() {
        for size in [1000, 4096, 65536, 1_000_000] {
            let padded = padme_length(size);
            let overhead = (padded - size) as f64 / size as f64;
            assert!(overhead <= 0.12, "overhead for {size} was {overhead:.3}");
        }
    }

    #[test]
    fn pad_unpad_round_trip() {
        let data = b"hello world this is test data";
        let padded = pad(data);
        assert!(padded.len() >= data.len());
        let unpadded = unpad(&padded, data.len());
        assert_eq!(unpadded, data);
    }
}
```

Run: `cargo test format::padding` -- expect FAIL

**Step 2: Implement**

```rust
use rand::rngs::OsRng;
use rand::RngCore;

fn ilog2(n: usize) -> u32 {
    (usize::BITS - 1) - n.leading_zeros()
}

pub fn padme_length(len: usize) -> usize {
    if len <= 256 {
        return 256;
    }
    let e = ilog2(len);
    let s = ilog2(e as usize) + 1;
    let last_bits = e - s;
    let bit_mask = (1usize << last_bits) - 1;
    (len + bit_mask) & !bit_mask
}

pub fn pad(data: &[u8]) -> Vec<u8> {
    let padded_len = padme_length(data.len());
    let mut out = data.to_vec();
    let pad_len = padded_len - data.len();
    if pad_len > 0 {
        let mut padding = vec![0u8; pad_len];
        OsRng.fill_bytes(&mut padding);
        out.extend_from_slice(&padding);
    }
    out
}

pub fn unpad(data: &[u8], original_size: usize) -> Vec<u8> {
    data[..original_size].to_vec()
}
```

Run: `cargo test format::padding` -- expect PASS

**Step 3: Commit**

```bash
git add src/format/padding.rs && git commit -m "feat: add PADME padding with integer math" && git push
```

---

### Task 14: InnerHeader

**Depends on:** T2
**Files:**
- Modify: `src/format/inner.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inner_header_round_trip() {
        let header = InnerHeader {
            filename: "secret.json".into(),
            original_size: 12345,
            checksum: [0xAA; 64],
            sealed_at: 1700000000,
            tomb_version: "0.1.0".into(),
            note: Some("test note".into()),
        };
        let bytes = header.serialize();
        let (parsed, consumed) = InnerHeader::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.filename, "secret.json");
        assert_eq!(parsed.original_size, 12345);
        assert_eq!(parsed.checksum, [0xAA; 64]);
        assert_eq!(parsed.sealed_at, 1700000000);
        assert_eq!(parsed.tomb_version, "0.1.0");
        assert_eq!(parsed.note.as_deref(), Some("test note"));
    }

    #[test]
    fn inner_header_no_note() {
        let header = InnerHeader {
            filename: "file.txt".into(),
            original_size: 100,
            checksum: [0u8; 64],
            sealed_at: 0,
            tomb_version: "0.1.0".into(),
            note: None,
        };
        let bytes = header.serialize();
        let (parsed, _) = InnerHeader::deserialize(&bytes).unwrap();
        assert!(parsed.note.is_none());
    }
}
```

Run: `cargo test format::inner` -- expect FAIL

**Step 2: Implement**

```rust
use crate::{Error, Result};

pub struct InnerHeader {
    pub filename: String,
    pub original_size: u64,
    pub checksum: [u8; 64],
    pub sealed_at: u64,
    pub tomb_version: String,
    pub note: Option<String>,
}

impl InnerHeader {
    /// Serialize: [filename_len:2 LE][filename][original_size:8 LE][checksum:64]
    ///            [sealed_at:8 LE][version_len:2 LE][version]
    ///            [has_note:1][note_len:2 LE][note]  (note fields only if has_note=1)
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        let fname = self.filename.as_bytes();
        out.extend_from_slice(&(fname.len() as u16).to_le_bytes());
        out.extend_from_slice(fname);

        out.extend_from_slice(&self.original_size.to_le_bytes());
        out.extend_from_slice(&self.checksum);
        out.extend_from_slice(&self.sealed_at.to_le_bytes());

        let ver = self.tomb_version.as_bytes();
        out.extend_from_slice(&(ver.len() as u16).to_le_bytes());
        out.extend_from_slice(ver);

        match &self.note {
            Some(note) => {
                out.push(1);
                let note_bytes = note.as_bytes();
                out.extend_from_slice(&(note_bytes.len() as u16).to_le_bytes());
                out.extend_from_slice(note_bytes);
            }
            None => {
                out.push(0);
            }
        }

        out
    }

    pub fn deserialize(data: &[u8]) -> Result<(Self, usize)> {
        let mut pos = 0;

        let read_u16 = |data: &[u8], pos: &mut usize| -> Result<u16> {
            if *pos + 2 > data.len() { return Err(Error::Format("truncated".into())); }
            let val = u16::from_le_bytes(data[*pos..*pos + 2].try_into().unwrap());
            *pos += 2;
            Ok(val)
        };

        let read_u64 = |data: &[u8], pos: &mut usize| -> Result<u64> {
            if *pos + 8 > data.len() { return Err(Error::Format("truncated".into())); }
            let val = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            Ok(val)
        };

        let fname_len = read_u16(data, &mut pos)? as usize;
        if pos + fname_len > data.len() { return Err(Error::Format("truncated filename".into())); }
        let filename = String::from_utf8(data[pos..pos + fname_len].to_vec())
            .map_err(|_| Error::Format("invalid utf8 filename".into()))?;
        pos += fname_len;

        let original_size = read_u64(data, &mut pos)?;

        if pos + 64 > data.len() { return Err(Error::Format("truncated checksum".into())); }
        let mut checksum = [0u8; 64];
        checksum.copy_from_slice(&data[pos..pos + 64]);
        pos += 64;

        let sealed_at = read_u64(data, &mut pos)?;

        let ver_len = read_u16(data, &mut pos)? as usize;
        if pos + ver_len > data.len() { return Err(Error::Format("truncated version".into())); }
        let tomb_version = String::from_utf8(data[pos..pos + ver_len].to_vec())
            .map_err(|_| Error::Format("invalid utf8 version".into()))?;
        pos += ver_len;

        if pos >= data.len() { return Err(Error::Format("truncated note flag".into())); }
        let has_note = data[pos];
        pos += 1;

        let note = if has_note == 1 {
            let note_len = read_u16(data, &mut pos)? as usize;
            if pos + note_len > data.len() { return Err(Error::Format("truncated note".into())); }
            let n = String::from_utf8(data[pos..pos + note_len].to_vec())
                .map_err(|_| Error::Format("invalid utf8 note".into()))?;
            pos += note_len;
            Some(n)
        } else {
            None
        };

        Ok((Self { filename, original_size, checksum, sealed_at, tomb_version, note }, pos))
    }
}
```

Run: `cargo test format::inner` -- expect PASS

**Step 3: Commit**

```bash
git add src/format/inner.rs && git commit -m "feat: add InnerHeader serialize/deserialize" && git push
```

---

### Task 15: PublicHeader

**Depends on:** T2
**Files:**
- Modify: `src/format/header.rs`
- Modify: `src/format/mod.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_header_round_trip() {
        let header = PublicHeader {
            version_major: 1,
            version_minor: 0,
            kdf_chain: vec![
                KdfDescriptor { id: 0x10, memory_mb: 1024, iterations: 1, parallelism: 1 },
                KdfDescriptor { id: 0x11, memory_mb: 1024, iterations: 4, parallelism: 4 },
            ],
            layers: vec![
                LayerDescriptor { id: 0x20, nonce_size: 16 },
                LayerDescriptor { id: 0x21, nonce_size: 16 },
                LayerDescriptor { id: 0x22, nonce_size: 24 },
            ],
            salt: vec![0xAA; 32],
            commitment: vec![0xBB; 32],
        };

        let bytes = header.serialize();
        assert_eq!(&bytes[..5], b"TOMB\n");

        let (parsed, consumed) = PublicHeader::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.version_major, 1);
        assert_eq!(parsed.version_minor, 0);
        assert_eq!(parsed.kdf_chain.len(), 2);
        assert_eq!(parsed.kdf_chain[0].id, 0x10);
        assert_eq!(parsed.kdf_chain[1].id, 0x11);
        assert_eq!(parsed.layers.len(), 3);
        assert_eq!(parsed.salt.len(), 32);
        assert_eq!(parsed.commitment.len(), 32);
    }

    #[test]
    fn public_header_magic_bytes() {
        let header = PublicHeader {
            version_major: 1,
            version_minor: 0,
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

Run: `cargo test format::header` -- expect FAIL

**Step 2: Implement**

```rust
use crate::{Error, Result};

pub struct KdfDescriptor {
    pub id: u8,
    pub memory_mb: u32,
    pub iterations: u32,
    pub parallelism: u8,
}

pub struct LayerDescriptor {
    pub id: u8,
    pub nonce_size: u8,
}

pub struct PublicHeader {
    pub version_major: u8,
    pub version_minor: u8,
    pub kdf_chain: Vec<KdfDescriptor>,
    pub layers: Vec<LayerDescriptor>,
    pub salt: Vec<u8>,
    pub commitment: Vec<u8>,
}

impl PublicHeader {
    /// Serialize: [TOMB\n][ver_major:1][ver_minor:1]
    ///   [kdf_count:1][foreach: id:1, memory_mb:4 LE, iterations:4 LE, parallelism:1]
    ///   [layer_count:1][foreach: id:1, nonce_size:1]
    ///   [salt:32][commitment:32]
    ///   [header_len:4 LE] (total length including this field)
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        out.extend_from_slice(b"TOMB\n");
        out.push(self.version_major);
        out.push(self.version_minor);

        out.push(self.kdf_chain.len() as u8);
        for kdf in &self.kdf_chain {
            out.push(kdf.id);
            out.extend_from_slice(&kdf.memory_mb.to_le_bytes());
            out.extend_from_slice(&kdf.iterations.to_le_bytes());
            out.push(kdf.parallelism);
        }

        out.push(self.layers.len() as u8);
        for layer in &self.layers {
            out.push(layer.id);
            out.push(layer.nonce_size);
        }

        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.commitment);

        let total_len = (out.len() + 4) as u32;
        out.extend_from_slice(&total_len.to_le_bytes());

        out
    }

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
            if pos + 10 > data.len() { return Err(Error::Format("truncated kdf".into())); }
            let id = data[pos];
            let memory_mb = u32::from_le_bytes(data[pos + 1..pos + 5].try_into().unwrap());
            let iterations = u32::from_le_bytes(data[pos + 5..pos + 9].try_into().unwrap());
            let parallelism = data[pos + 9];
            pos += 10;
            kdf_chain.push(KdfDescriptor { id, memory_mb, iterations, parallelism });
        }

        if pos >= data.len() { return Err(Error::Format("truncated layer count".into())); }
        let layer_count = data[pos] as usize;
        pos += 1;

        let mut layers = Vec::with_capacity(layer_count);
        for _ in 0..layer_count {
            if pos + 2 > data.len() { return Err(Error::Format("truncated layer".into())); }
            let id = data[pos];
            let nonce_size = data[pos + 1];
            pos += 2;
            layers.push(LayerDescriptor { id, nonce_size });
        }

        if pos + 64 > data.len() { return Err(Error::Format("truncated salt/commitment".into())); }
        let salt = data[pos..pos + 32].to_vec();
        pos += 32;
        let commitment = data[pos..pos + 32].to_vec();
        pos += 32;

        if pos + 4 > data.len() { return Err(Error::Format("truncated header length".into())); }
        let header_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        if pos != header_len {
            return Err(Error::Format(format!("header length mismatch: expected {header_len}, got {pos}")));
        }

        Ok((Self { version_major, version_minor, kdf_chain, layers, salt, commitment }, pos))
    }
}
```

**Step 3: Update `src/format/mod.rs`**

```rust
pub mod header;
pub mod inner;
pub mod padding;

pub use header::{PublicHeader, KdfDescriptor, LayerDescriptor};
pub use inner::InnerHeader;
```

Run: `cargo test format::header` -- expect PASS

**Step 4: Commit**

```bash
git add src/format/ && git commit -m "feat: add PublicHeader serialize/deserialize" && git push
```

---

### Task 16: LayerEnvelope

**Depends on:** T2, T3
**Files:**
- Modify: `src/pipeline/envelope.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::LayerKey;

    #[test]
    fn envelope_round_trip() {
        let mac_key = LayerKey([0xDD; 32]);
        let nonce = vec![1u8; 16];
        let payload = vec![2u8; 100];
        let mac = LayerEnvelope::compute_mac(&mac_key, 0x20, &nonce, &payload);

        let env = LayerEnvelope {
            layer_id: 0x20,
            nonce: nonce.clone(),
            payload: payload.clone(),
            mac,
        };

        let bytes = env.serialize();
        let parsed = LayerEnvelope::deserialize(&bytes).unwrap();

        assert_eq!(parsed.layer_id, 0x20);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.mac, mac);
    }

    #[test]
    fn envelope_mac_verification_passes() {
        let mac_key = LayerKey([0xEE; 32]);
        let nonce = vec![3u8; 24];
        let payload = vec![4u8; 50];
        let mac = LayerEnvelope::compute_mac(&mac_key, 0x22, &nonce, &payload);

        let env = LayerEnvelope { layer_id: 0x22, nonce, payload, mac };
        assert!(env.verify_mac(&mac_key));
    }

    #[test]
    fn envelope_tampered_payload_fails_mac() {
        let mac_key = LayerKey([0xFF; 32]);
        let nonce = vec![5u8; 16];
        let payload = vec![6u8; 50];
        let mac = LayerEnvelope::compute_mac(&mac_key, 0x21, &nonce, &payload);

        let mut tampered_payload = payload;
        tampered_payload[0] ^= 0xFF;

        let env = LayerEnvelope { layer_id: 0x21, nonce, payload: tampered_payload, mac };
        assert!(!env.verify_mac(&mac_key));
    }

    #[test]
    fn envelope_wrong_key_fails_mac() {
        let mac_key = LayerKey([0xAA; 32]);
        let wrong_key = LayerKey([0xBB; 32]);
        let nonce = vec![7u8; 16];
        let payload = vec![8u8; 50];
        let mac = LayerEnvelope::compute_mac(&mac_key, 0x20, &nonce, &payload);

        let env = LayerEnvelope { layer_id: 0x20, nonce, payload, mac };
        assert!(!env.verify_mac(&wrong_key));
    }
}
```

Run: `cargo test pipeline::envelope` -- expect FAIL

**Step 2: Implement**

```rust
use crate::key::LayerKey;
use crate::{Error, Result};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub struct LayerEnvelope {
    pub layer_id: u8,
    pub nonce: Vec<u8>,
    pub payload: Vec<u8>,
    pub mac: [u8; 32],
}

impl LayerEnvelope {
    /// Serialize: [layer_id:1][nonce_len:1][nonce:N][payload_len:8 LE][payload:M][mac:32]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.layer_id);
        out.push(self.nonce.len() as u8);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.mac);
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::Format("envelope too short".into()));
        }

        let layer_id = data[0];
        let nonce_len = data[1] as usize;

        let payload_len_start = 2usize.checked_add(nonce_len)
            .ok_or_else(|| Error::Format("nonce length overflow".into()))?;
        let payload_len_end = payload_len_start.checked_add(8)
            .ok_or_else(|| Error::Format("payload length overflow".into()))?;

        if data.len() < payload_len_end {
            return Err(Error::Format("truncated envelope header".into()));
        }

        let nonce = data[2..payload_len_start].to_vec();
        let payload_len = u64::from_le_bytes(
            data[payload_len_start..payload_len_end].try_into().unwrap()
        ) as usize;

        let payload_start = payload_len_end;
        let payload_end = payload_start.checked_add(payload_len)
            .ok_or_else(|| Error::Format("payload size overflow".into()))?;
        let mac_end = payload_end.checked_add(32)
            .ok_or_else(|| Error::Format("mac offset overflow".into()))?;

        if data.len() < mac_end {
            return Err(Error::Format("truncated envelope body".into()));
        }

        let payload = data[payload_start..payload_end].to_vec();
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[payload_end..mac_end]);

        Ok(Self { layer_id, nonce, payload, mac })
    }

    /// Compute HMAC-SHA256 over [layer_id || nonce || payload]
    pub fn compute_mac(mac_key: &LayerKey, layer_id: u8, nonce: &[u8], payload: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(mac_key.as_bytes())
            .expect("HMAC key size is always valid");
        mac.update(&[layer_id]);
        mac.update(nonce);
        mac.update(payload);
        let result = mac.finalize().into_bytes();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }

    /// Verify HMAC tag (constant-time)
    pub fn verify_mac(&self, mac_key: &LayerKey) -> bool {
        let expected = Self::compute_mac(mac_key, self.layer_id, &self.nonce, &self.payload);
        bool::from(self.mac.ct_eq(&expected))
    }
}
```

**Step 3: Update `src/pipeline/mod.rs`**

```rust
pub mod envelope;
```

Run: `cargo test pipeline::envelope` -- expect PASS

**Step 4: Commit**

```bash
git add src/pipeline/ && git commit -m "feat: add LayerEnvelope with HMAC-SHA256 auth" && git push
```

---

### Stream D: Passphrase

### Task 17: EFF Wordlist

**Depends on:** T1
**Files:**
- Modify: `src/passphrase/wordlist.rs`

**Step 1: Download and embed the EFF large wordlist**

The EFF large wordlist contains 7,776 words. Download it and convert to a Rust const array.

```bash
# Download the EFF wordlist
curl -s https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt \
  | awk '{print $2}' \
  | sort \
  > /tmp/eff_words.txt

# Verify count
wc -l /tmp/eff_words.txt
# Expected: 7776
```

Generate `src/passphrase/wordlist.rs`:

```bash
echo 'pub const EFF_WORDLIST: [&str; 7776] = [' > src/passphrase/wordlist.rs
awk '{printf "    \"%s\",\n", $1}' /tmp/eff_words.txt >> src/passphrase/wordlist.rs
echo '];' >> src/passphrase/wordlist.rs
```

**Step 2: Write test**

Add at the bottom of `src/passphrase/wordlist.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_7776_words() {
        assert_eq!(EFF_WORDLIST.len(), 7776);
    }

    #[test]
    fn wordlist_contains_known_words() {
        assert!(EFF_WORDLIST.contains(&"abandon"));
        assert!(EFF_WORDLIST.contains(&"zoom"));
    }

    #[test]
    fn wordlist_is_sorted() {
        for window in EFF_WORDLIST.windows(2) {
            assert!(window[0] <= window[1], "{} should come before {}", window[0], window[1]);
        }
    }
}
```

Run: `cargo test passphrase::wordlist` -- expect PASS

**Step 3: Update `src/passphrase/mod.rs`**

```rust
pub mod wordlist;
pub mod generate;
```

**Step 4: Commit**

```bash
git add src/passphrase/ && git commit -m "feat: embed EFF diceware wordlist (7776 words)" && git push
```

---

### Task 18: Passphrase Validation

**Depends on:** T2, T17
**Files:**
- Modify: `src/passphrase/mod.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_21_valid_words() {
        // Pick 21 words known to be in the EFF list
        let words: Vec<&str> = wordlist::EFF_WORDLIST[..21].to_vec();
        let input = words.join(" ");
        assert!(validate_passphrase(&input).is_ok());
    }

    #[test]
    fn validate_rejects_20_words() {
        let words: Vec<&str> = wordlist::EFF_WORDLIST[..20].to_vec();
        let input = words.join(" ");
        assert!(validate_passphrase(&input).is_err());
    }

    #[test]
    fn validate_rejects_22_words() {
        let words: Vec<&str> = wordlist::EFF_WORDLIST[..22].to_vec();
        let input = words.join(" ");
        assert!(validate_passphrase(&input).is_err());
    }

    #[test]
    fn validate_rejects_non_eff_word() {
        let mut words: Vec<String> = wordlist::EFF_WORDLIST[..20]
            .iter().map(|w| w.to_string()).collect();
        words.push("xyzzyplugh".into()); // not in EFF list
        let input = words.join(" ");
        let err = validate_passphrase(&input).unwrap_err();
        assert!(format!("{err}").contains("xyzzyplugh"));
    }
}
```

Run: `cargo test passphrase::tests` -- expect FAIL

**Step 2: Implement**

Add to `src/passphrase/mod.rs`:

```rust
pub mod wordlist;
pub mod generate;

use crate::{Error, Result};

pub fn validate_passphrase(input: &str) -> Result<()> {
    let words: Vec<&str> = input.split_whitespace().collect();
    if words.len() != 21 {
        return Err(Error::PassphraseInvalid(
            format!("expected 21 words, got {}", words.len())
        ));
    }
    for word in &words {
        if !wordlist::EFF_WORDLIST.contains(word) {
            return Err(Error::WordNotInList(word.to_string()));
        }
    }
    Ok(())
}
```

Run: `cargo test passphrase::tests` -- expect PASS

**Step 3: Commit**

```bash
git add src/passphrase/mod.rs && git commit -m "feat: add passphrase validation (21 EFF words)" && git push
```

---

### Task 19: Passphrase Generation

**Depends on:** T17
**Files:**
- Modify: `src/passphrase/generate.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::passphrase::wordlist::EFF_WORDLIST;

    #[test]
    fn generate_produces_21_words() {
        let words = generate_passphrase(21);
        assert_eq!(words.len(), 21);
    }

    #[test]
    fn generate_all_words_in_list() {
        let words = generate_passphrase(21);
        for word in &words {
            assert!(EFF_WORDLIST.contains(&word.as_str()), "'{word}' not in EFF list");
        }
    }

    #[test]
    fn generate_produces_different_output() {
        let a = generate_passphrase(21);
        let b = generate_passphrase(21);
        // Astronomically unlikely to be equal
        assert_ne!(a, b);
    }
}
```

Run: `cargo test passphrase::generate` -- expect FAIL

**Step 2: Implement**

```rust
use crate::passphrase::wordlist::EFF_WORDLIST;

use rand::rngs::OsRng;
use rand::Rng;

pub fn generate_passphrase(word_count: usize) -> Vec<String> {
    let mut words = Vec::with_capacity(word_count);
    for _ in 0..word_count {
        let index = OsRng.gen_range(0..EFF_WORDLIST.len());
        words.push(EFF_WORDLIST[index].to_string());
    }
    words
}
```

Run: `cargo test passphrase::generate` -- expect PASS

**Step 3: Commit**

```bash
git add src/passphrase/generate.rs && git commit -m "feat: add passphrase generation with CSPRNG" && git push
```

---

## Phase 3: Pipeline

> Requires Stream A (ciphers) and Stream C (format/envelope) to be complete.

### Task 20: Pipeline + Seal

**Depends on:** T4-T7, T11, T16
**Files:**
- Modify: `src/pipeline/mod.rs`

**Step 1: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::LayerKey;
    use crate::key::expand::{LayerState, LayerInfo, expand_layer_keys};
    use crate::key::MasterKey;

    fn test_states() -> Vec<LayerState> {
        let master = MasterKey([0xAA; 32]);
        let layer_info = vec![
            LayerInfo { encrypt_label: "tomb-twofish-256-ctr", mac_label: "tomb-twofish-256-ctr-mac", nonce_size: 16 },
            LayerInfo { encrypt_label: "tomb-aes-256-ctr", mac_label: "tomb-aes-256-ctr-mac", nonce_size: 16 },
            LayerInfo { encrypt_label: "tomb-xchacha20", mac_label: "tomb-xchacha20-mac", nonce_size: 24 },
        ];
        expand_layer_keys(&master, &layer_info).unwrap()
    }

    #[test]
    fn pipeline_seal_produces_output() {
        let pipeline = Pipeline::default_tomb();
        let states = test_states();
        let plaintext = b"hello tomb pipeline test";
        let sealed = pipeline.seal(&states, plaintext).unwrap();
        assert!(!sealed.is_empty());
        assert_ne!(&sealed, plaintext);
    }

    #[test]
    fn pipeline_seal_then_open_round_trip() {
        let pipeline = Pipeline::default_tomb();
        let states = test_states();
        let plaintext = b"round trip test data for tomb pipeline!!";
        let sealed = pipeline.seal(&states, plaintext).unwrap();
        let opened = pipeline.open(&states, &sealed).unwrap();
        assert_eq!(&opened, plaintext);
    }

    #[test]
    fn pipeline_descriptors() {
        let pipeline = Pipeline::default_tomb();
        let descs = pipeline.layer_descriptors();
        assert_eq!(descs.len(), 3);
        assert_eq!(descs[0].id, 0x20);
        assert_eq!(descs[1].id, 0x21);
        assert_eq!(descs[2].id, 0x22);
    }
}
```

Run: `cargo test pipeline::tests` -- expect FAIL

**Step 2: Implement**

```rust
pub mod envelope;

use crate::cipher::CipherLayer;
use crate::cipher::twofish::TwofishCtr;
use crate::cipher::aes::AesCtr;
use crate::cipher::xchacha::XChaCha;
use crate::cipher::lookup::cipher_by_id;
use crate::key::expand::LayerState;
use crate::format::header::{PublicHeader, LayerDescriptor};
use crate::pipeline::envelope::LayerEnvelope;
use crate::{Error, Result};

pub struct Pipeline {
    pub(crate) layers: Vec<Box<dyn CipherLayer>>,
}

impl Pipeline {
    pub fn default_tomb() -> Self {
        Self {
            layers: vec![
                Box::new(TwofishCtr),
                Box::new(AesCtr),
                Box::new(XChaCha),
            ],
        }
    }

    pub fn layer_descriptors(&self) -> Vec<LayerDescriptor> {
        self.layers.iter()
            .map(|l| LayerDescriptor { id: l.id(), nonce_size: l.nonce_size() as u8 })
            .collect()
    }

    pub fn layer_info(&self) -> Vec<crate::key::expand::LayerInfo> {
        self.layers.iter()
            .map(|l| crate::key::expand::LayerInfo {
                encrypt_label: l.encrypt_label(),
                mac_label: l.mac_label(),
                nonce_size: l.nonce_size(),
            })
            .collect()
    }

    pub fn seal(&self, states: &[LayerState], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut data = plaintext.to_vec();

        for (layer, state) in self.layers.iter().zip(states.iter()) {
            let encrypted = layer.encrypt(&state.encrypt_key, &state.nonce, &data)?;
            let mac = LayerEnvelope::compute_mac(
                &state.mac_key, layer.id(), &state.nonce, &encrypted,
            );
            data = LayerEnvelope {
                layer_id: layer.id(),
                nonce: state.nonce.clone(),
                payload: encrypted,
                mac,
            }.serialize();
        }

        Ok(data)
    }

    pub fn open(&self, states: &[LayerState], sealed: &[u8]) -> Result<Vec<u8>> {
        let mut data = sealed.to_vec();

        for (layer, state) in self.layers.iter().zip(states.iter()).rev() {
            let env = LayerEnvelope::deserialize(&data)?;

            if !env.verify_mac(&state.mac_key) {
                return Err(Error::DecryptionFailed);
            }

            data = layer.decrypt(&state.encrypt_key, &env.nonce, &env.payload)?;
        }

        Ok(data)
    }

    pub fn build_from_header(header: &PublicHeader) -> Result<Self> {
        let layers: Vec<Box<dyn CipherLayer>> = header.layers.iter()
            .map(|desc| cipher_by_id(desc.id))
            .collect::<Result<_>>()?;
        Ok(Self { layers })
    }
}
```

Run: `cargo test pipeline::tests` -- expect PASS

**Step 3: Commit**

```bash
git add src/pipeline/mod.rs && git commit -m "feat: add Pipeline with seal/open and 3-layer encryption" && git push
```

---

### Task 21: Pipeline Tamper Detection Test

**Depends on:** T20
**Files:**
- Modify: `src/pipeline/mod.rs` (add tests)

**Step 1: Add tamper detection tests**

```rust
    #[test]
    fn pipeline_tampered_data_fails() {
        let pipeline = Pipeline::default_tomb();
        let states = test_states();
        let plaintext = b"tamper detection test";
        let mut sealed = pipeline.seal(&states, plaintext).unwrap();
        // Flip a byte in the middle of the sealed data
        let mid = sealed.len() / 2;
        sealed[mid] ^= 0xFF;
        assert!(pipeline.open(&states, &sealed).is_err());
    }

    #[test]
    fn pipeline_build_from_header() {
        let pipeline = Pipeline::default_tomb();
        let header = PublicHeader {
            version_major: 1,
            version_minor: 0,
            kdf_chain: vec![],
            layers: pipeline.layer_descriptors(),
            salt: vec![0; 32],
            commitment: vec![0; 32],
        };
        let rebuilt = Pipeline::build_from_header(&header).unwrap();
        assert_eq!(rebuilt.layers.len(), 3);
        assert_eq!(rebuilt.layers[0].id(), 0x20);
        assert_eq!(rebuilt.layers[1].id(), 0x21);
        assert_eq!(rebuilt.layers[2].id(), 0x22);
    }
```

Run: `cargo test pipeline::tests` -- expect PASS

**Step 2: Commit**

```bash
git add src/pipeline/mod.rs && git commit -m "test: add pipeline tamper detection and header rebuild tests" && git push
```

---

## Phase 4: Library API

> Requires Phase 2 (all streams) and Phase 3 (pipeline) to be complete.

### Task 22: prepare_payload

**Depends on:** T13, T14
**Files:**
- Modify: `src/lib.rs`

**Step 1: Write test**

```rust
    #[test]
    fn prepare_payload_includes_checksum() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("tomb_test_prepare");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        let prepared = prepare_payload(&file_path, Some("test note")).unwrap();
        assert!(!prepared.padded.is_empty());
        assert_eq!(prepared.checksum.len(), 64);
        assert_eq!(prepared.inner.filename, "test.txt");
        assert_eq!(prepared.inner.original_size, 11);
        assert_eq!(prepared.inner.note.as_deref(), Some("test note"));

        std::fs::remove_dir_all(&dir).ok();
    }
```

Run: `cargo test prepare_payload` -- expect FAIL

**Step 2: Implement**

Add to `src/lib.rs`:

```rust
use std::path::Path;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Sha512, Digest};
use zeroize::Zeroize;

use crate::format::inner::InnerHeader;
use crate::format::padding;

pub struct PreparedPayload {
    pub padded: Vec<u8>,
    pub checksum: [u8; 64],
    pub inner: InnerHeader,
}

pub fn prepare_payload(input_path: &Path, note: Option<&str>) -> Result<PreparedPayload> {
    let plaintext = fs::read(input_path)?;
    let checksum: [u8; 64] = Sha512::digest(&plaintext).into();

    let inner = InnerHeader {
        filename: input_path.file_name()
            .ok_or_else(|| Error::Format("no filename".into()))?
            .to_string_lossy()
            .into(),
        original_size: plaintext.len() as u64,
        checksum,
        sealed_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        tomb_version: env!("CARGO_PKG_VERSION").into(),
        note: note.map(String::from),
    };

    let mut payload = inner.serialize();
    payload.extend_from_slice(&plaintext);
    let padded = padding::pad(&payload);
    payload.zeroize();

    Ok(PreparedPayload { padded, checksum, inner })
}
```

Run: `cargo test prepare_payload` -- expect PASS

**Step 3: Commit**

```bash
git add src/lib.rs && git commit -m "feat: add prepare_payload function" && git push
```

---

### Task 23: derive_keys

**Depends on:** T10, T11, T12, T20
**Files:**
- Modify: `src/lib.rs`

**Step 1: Write test**

```rust
    #[test]
    fn derive_keys_produces_states() {
        let passphrase = key::Passphrase::new(b"test passphrase words here".to_vec());
        let pipeline = pipeline::Pipeline::default_tomb();
        let keys = derive_keys_with_params(&passphrase, &pipeline).unwrap();
        assert_eq!(keys.states.len(), 3);
        assert_eq!(keys.salt.len(), 32);
        assert_eq!(keys.commitment.as_bytes().len(), 32);
    }
```

Run: `cargo test derive_keys_produces` -- expect FAIL

**Step 2: Implement**

```rust
use crate::key::{MasterKey, Passphrase, Commitment};
use crate::key::derive::{Derive, ScryptDerive, Argon2idDerive, chain_derive};
use crate::key::expand::{LayerState, expand_layer_keys};
use crate::key::commit::compute_commitment;
use crate::pipeline::Pipeline;

pub struct DerivedKeys {
    pub master: MasterKey,
    pub states: Vec<LayerState>,
    pub commitment: Commitment,
    pub salt: Vec<u8>,
}

/// Production key derivation (1GB scrypt + 1GB Argon2id)
pub fn derive_keys(passphrase: &Passphrase, pipeline: &Pipeline) -> Result<DerivedKeys> {
    derive_keys_internal(
        passphrase,
        pipeline,
        ScryptDerive::production(),
        Argon2idDerive::production(),
    )
}

/// Test key derivation (tiny params, fast)
pub fn derive_keys_with_params(passphrase: &Passphrase, pipeline: &Pipeline) -> Result<DerivedKeys> {
    derive_keys_internal(
        passphrase,
        pipeline,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    )
}

fn derive_keys_internal(
    passphrase: &Passphrase,
    pipeline: &Pipeline,
    scrypt: ScryptDerive,
    argon2: Argon2idDerive,
) -> Result<DerivedKeys> {
    let salt = random_bytes(32);

    let kdfs: Vec<Box<dyn Derive>> = vec![
        Box::new(scrypt),
        Box::new(argon2),
    ];
    let master = chain_derive(&kdfs, passphrase.as_bytes(), &salt)?;

    let layer_info = pipeline.layer_info();
    let states = expand_layer_keys(&master, &layer_info)?;
    let commitment = compute_commitment(&master);

    Ok(DerivedKeys { master, states, commitment, salt })
}
```

Run: `cargo test derive_keys_produces` -- expect PASS

**Step 3: Commit**

```bash
git add src/lib.rs && git commit -m "feat: add derive_keys with chained KDF" && git push
```

---

### Task 24: encrypt_and_write + verify_sealed

**Depends on:** T15, T20, T23
**Files:**
- Modify: `src/lib.rs`

**Step 1: Implement encrypt_and_write**

```rust
pub fn encrypt_and_write(
    output_path: &Path,
    header: &format::PublicHeader,
    pipeline: &Pipeline,
    states: &[LayerState],
    padded: &[u8],
) -> Result<()> {
    let sealed = pipeline.seal(states, padded)?;

    let header_bytes = header.serialize();
    let mut tomb_data = header_bytes;
    tomb_data.extend_from_slice(&sealed);

    // Atomic write: tmp file then rename
    let temp_path = output_path.with_extension("tomb.tmp");
    fs::write(&temp_path, &tomb_data)?;
    fs::rename(&temp_path, output_path)?;

    Ok(())
}
```

**Step 2: Implement open_file (needed by verify)**

```rust
pub struct OpenedFile {
    pub data: Vec<u8>,
    pub filename: String,
}

pub fn open_file(
    file_path: &Path,
    passphrase: &Passphrase,
) -> Result<OpenedFile> {
    open_file_with_params(file_path, passphrase, ScryptDerive::production(), Argon2idDerive::production())
}

pub fn open_file_with_params(
    file_path: &Path,
    passphrase: &Passphrase,
    scrypt: ScryptDerive,
    argon2: Argon2idDerive,
) -> Result<OpenedFile> {
    let tomb_data = fs::read(file_path)?;
    let (header, header_len) = format::PublicHeader::deserialize(&tomb_data)?;

    // Verify key commitment
    let kdfs: Vec<Box<dyn Derive>> = vec![Box::new(scrypt), Box::new(argon2)];
    let master = chain_derive(&kdfs, passphrase.as_bytes(), &header.salt)?;
    let commitment = compute_commitment(&master);
    let stored = Commitment(header.commitment.as_slice().try_into()
        .map_err(|_| Error::Format("invalid commitment length".into()))?);
    if !commitment.verify(&stored) {
        return Err(Error::DecryptionFailed);
    }

    let pipeline = Pipeline::build_from_header(&header)?;
    let layer_info = pipeline.layer_info();
    let states = expand_layer_keys(&master, &layer_info)?;

    let sealed_body = &tomb_data[header_len..];
    let decrypted = pipeline.open(&states, sealed_body)?;

    // Parse inner header
    let (inner, inner_len) = format::InnerHeader::deserialize(&decrypted)?;
    let plaintext = &decrypted[inner_len..inner_len + inner.original_size as usize];

    // Verify SHA-512 checksum
    let checksum: [u8; 64] = Sha512::digest(plaintext).into();
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&checksum[..], &inner.checksum[..])) {
        return Err(Error::DecryptionFailed);
    }

    Ok(OpenedFile {
        data: plaintext.to_vec(),
        filename: inner.filename,
    })
}

pub fn verify_sealed(
    output_path: &Path,
    passphrase: &Passphrase,
    expected_checksum: &[u8; 64],
) -> Result<()> {
    let opened = open_file_with_params(
        output_path,
        passphrase,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    )?;
    let checksum: [u8; 64] = Sha512::digest(&opened.data).into();
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&checksum[..], &expected_checksum[..])) {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}
```

**Step 3: Commit**

```bash
git add src/lib.rs && git commit -m "feat: add encrypt_and_write, open_file, verify_sealed" && git push
```

---

### Task 25: seal + open Orchestrators (Full Round-Trip)

**Depends on:** T22, T23, T24
**Files:**
- Modify: `src/lib.rs`

**Step 1: Write integration test**

```rust
    #[test]
    fn seal_and_open_round_trip() {
        let dir = std::env::temp_dir().join("tomb_test_roundtrip");
        std::fs::create_dir_all(&dir).unwrap();

        let input = dir.join("secret.txt");
        let output = dir.join("secret.tomb");
        std::fs::write(&input, b"top secret data for tomb test").unwrap();

        let passphrase = key::Passphrase::new(b"test passphrase".to_vec());

        seal_with_params(&input, &output, &passphrase, Some("test note")).unwrap();
        assert!(output.exists());

        let opened = open_file_with_params(
            &output,
            &passphrase,
            key::derive::ScryptDerive::test(),
            key::derive::Argon2idDerive::test(),
        ).unwrap();
        assert_eq!(opened.data, b"top secret data for tomb test");
        assert_eq!(opened.filename, "secret.txt");

        std::fs::remove_dir_all(&dir).ok();
    }
```

Run: `cargo test seal_and_open` -- expect FAIL

**Step 2: Implement seal_with_params**

```rust
pub fn seal_with_params(
    input_path: &Path,
    output_path: &Path,
    passphrase: &Passphrase,
    note: Option<&str>,
) -> Result<()> {
    let prepared = prepare_payload(input_path, note)?;
    let pipeline = Pipeline::default_tomb();
    let keys = derive_keys_with_params(passphrase, &pipeline)?;

    let header = format::PublicHeader {
        version_major: 1,
        version_minor: 0,
        kdf_chain: vec![
            format::KdfDescriptor { id: 0x10, memory_mb: 1, iterations: 1, parallelism: 1 },
            format::KdfDescriptor { id: 0x11, memory_mb: 1, iterations: 1, parallelism: 1 },
        ],
        layers: pipeline.layer_descriptors(),
        salt: keys.salt.clone(),
        commitment: keys.commitment.as_bytes().to_vec(),
    };

    encrypt_and_write(output_path, &header, &pipeline, &keys.states, &prepared.padded)?;

    // Verify the sealed file
    verify_sealed(output_path, passphrase, &prepared.checksum)?;

    Ok(())
}

pub fn seal(
    input_path: &Path,
    output_path: &Path,
    passphrase: &Passphrase,
    note: Option<&str>,
) -> Result<()> {
    let prepared = prepare_payload(input_path, note)?;
    let pipeline = Pipeline::default_tomb();
    let keys = derive_keys(passphrase, &pipeline)?;

    let header = format::PublicHeader {
        version_major: 1,
        version_minor: 0,
        kdf_chain: vec![
            format::KdfDescriptor { id: 0x10, memory_mb: 1024, iterations: 1, parallelism: 1 },
            format::KdfDescriptor { id: 0x11, memory_mb: 1024, iterations: 4, parallelism: 4 },
        ],
        layers: pipeline.layer_descriptors(),
        salt: keys.salt.clone(),
        commitment: keys.commitment.as_bytes().to_vec(),
    };

    encrypt_and_write(output_path, &header, &pipeline, &keys.states, &prepared.padded)?;
    verify_sealed(output_path, passphrase, &prepared.checksum)?;

    Ok(())
}

pub fn inspect_file(file_path: &Path) -> Result<format::PublicHeader> {
    let data = fs::read(file_path)?;
    let (header, _) = format::PublicHeader::deserialize(&data)?;
    Ok(header)
}
```

Run: `cargo test seal_and_open` -- expect PASS

**Step 3: Commit**

```bash
git add src/lib.rs && git commit -m "feat: add seal and open orchestrators with verification" && git push
```

---

## Phase 5: CLI

> Requires Phase 4 and Stream D (passphrase) to be complete.

### Task 26: Clap CLI Structure + Inspect Command

**Depends on:** T15, T25
**Files:**
- Modify: `src/cli.rs`

**Step 1: Implement CLI parsing and inspect**

```rust
use std::path::PathBuf;
use std::fs;

use clap::{Parser, Subcommand};

use crate::{Error, Result};

#[derive(Parser)]
#[command(name = "tomb", about = "Encrypt anything with a passphrase. Recover it decades later.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Encrypt a file
    Seal {
        file: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Decrypt a file
    Open {
        file: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Confirm a file is decryptable
    Verify {
        file: PathBuf,
    },
    /// View public header (no passphrase needed)
    Inspect {
        file: PathBuf,
    },
    /// Generate a 21-word passphrase
    Generate,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Inspect { file } => {
            let header = crate::inspect_file(&file)?;
            println!("tomb file: {}", file.display());
            println!("format version: {}.{}", header.version_major, header.version_minor);
            println!("KDF chain ({} stages):", header.kdf_chain.len());
            for kdf in &header.kdf_chain {
                let name = match kdf.id {
                    0x10 => "scrypt",
                    0x11 => "argon2id",
                    _ => "unknown",
                };
                println!("  {name} (0x{:02x}): {}MB memory, {} iterations, {} parallelism",
                    kdf.id, kdf.memory_mb, kdf.iterations, kdf.parallelism);
            }
            println!("cipher layers ({}):", header.layers.len());
            for layer in &header.layers {
                let name = match layer.id {
                    0x20 => "twofish-256-ctr + hmac-sha256",
                    0x21 => "aes-256-ctr + hmac-sha256",
                    0x22 => "xchacha20 + hmac-sha256",
                    _ => "unknown",
                };
                println!("  {name} (0x{:02x}), nonce: {} bytes", layer.id, layer.nonce_size);
            }
        }
        _ => {
            eprintln!("Command not yet implemented");
            std::process::exit(1);
        }
    }

    Ok(())
}
```

Run: `cargo build` -- expect compiles

**Step 2: Commit**

```bash
git add src/cli.rs && git commit -m "feat: add CLI structure with inspect command" && git push
```

---

### Task 27: Passphrase Prompts + Generate Command

**Depends on:** T18, T19, T26
**Files:**
- Modify: `src/cli.rs`

**Step 1: Add passphrase prompting and generate**

Add helper functions and the Generate command handler:

```rust
use crate::key::Passphrase;
use crate::passphrase::{validate_passphrase, generate::generate_passphrase};

use std::io::{self, Write};

fn prompt_passphrase(prompt: &str) -> Result<String> {
    let pass = rpassword::prompt_password(prompt)
        .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other, e)))?;
    Ok(pass)
}

fn prompt_passphrase_for_seal() -> Result<Passphrase> {
    println!("  1. Generate a secure passphrase (21 words)");
    println!("  2. Enter your own passphrase");
    print!("Choice: ");
    io::stdout().flush().ok();

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)
        .map_err(|e| Error::Io(e))?;

    match choice.trim() {
        "1" => {
            let words = generate_passphrase(21);

            // Alternate screen buffer
            print!("\x1b[?1049h");
            println!("\nYour passphrase (21 words):\n");
            for chunk in words.chunks(7) {
                println!("  {}", chunk.join(" "));
            }
            println!("\nWrite this down somewhere safe. Press Enter when done...");
            let mut buf = String::new();
            io::stdin().read_line(&mut buf).ok();
            print!("\x1b[?1049l");

            println!("Re-enter your passphrase to confirm:");
            let entered = prompt_passphrase("Passphrase: ")?;
            let generated = words.join(" ");
            if entered != generated {
                return Err(Error::PassphraseMismatch);
            }
            Ok(Passphrase::new(generated.into_bytes()))
        }
        "2" => {
            let p1 = prompt_passphrase("Enter passphrase (21 words from the EFF diceware list): ")?;
            validate_passphrase(&p1)?;
            let p2 = prompt_passphrase("Confirm passphrase: ")?;
            if p1 != p2 {
                return Err(Error::PassphraseMismatch);
            }
            Ok(Passphrase::new(p1.into_bytes()))
        }
        _ => Err(Error::Format("invalid choice".into())),
    }
}

fn prompt_passphrase_for_open() -> Result<Passphrase> {
    let pass = prompt_passphrase("Enter passphrase: ")?;
    Ok(Passphrase::new(pass.into_bytes()))
}
```

Add the Generate handler to the match in `run()`:

```rust
        Command::Generate => {
            let words = generate_passphrase(21);

            print!("\x1b[?1049h");
            println!("\nYour passphrase (21 words):\n");
            for chunk in words.chunks(7) {
                println!("  {}", chunk.join(" "));
            }
            println!("\nWrite this down somewhere safe. Press Enter when done...");
            let mut buf = String::new();
            io::stdin().read_line(&mut buf).ok();
            print!("\x1b[?1049l");
        }
```

Run: `cargo build` -- expect compiles

**Step 2: Commit**

```bash
git add src/cli.rs && git commit -m "feat: add passphrase prompting and generate command" && git push
```

---

### Task 28: Seal + Open + Verify Commands

**Depends on:** T25, T27
**Files:**
- Modify: `src/cli.rs`

**Step 1: Implement remaining commands**

Replace the `_ => { eprintln!("not implemented") }` catch-all with real handlers:

```rust
        Command::Seal { file, output, note } => {
            let output = output.unwrap_or_else(|| {
                let mut p = file.clone();
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                p.set_file_name(format!("{name}.tomb"));
                p
            });

            // Warn if output filename leaks original name
            let output_name = output.file_name().unwrap_or_default().to_string_lossy();
            let input_name = file.file_name().unwrap_or_default().to_string_lossy();
            if output_name.contains(input_name.as_ref()) && input_name.len() > 0 {
                eprintln!("Note: output filename '{}' contains the original filename.", output_name);
                eprintln!("Consider using -o with a neutral name to avoid leaking metadata.");
            }

            let passphrase = prompt_passphrase_for_seal()?;
            crate::seal(&file, &output, &passphrase, note.as_deref())?;

            let meta = fs::metadata(&output)?;
            println!("Sealed -> {} ({} bytes)", output.display(), meta.len());
            println!("Remember to delete the original file.");
        }
        Command::Open { file, output } => {
            let passphrase = prompt_passphrase_for_open()?;
            let result = crate::open_file(&file, &passphrase)?;
            let output = output.unwrap_or_else(|| PathBuf::from(&result.filename));
            fs::write(&output, &result.data)?;
            println!("Opened -> {}", output.display());
        }
        Command::Verify { file } => {
            let passphrase = prompt_passphrase_for_open()?;
            // For verify, we just open and discard the result
            crate::open_file(&file, &passphrase)?;
            println!("Verified. File is decryptable.");
        }
```

Run: `cargo build` -- expect compiles

**Step 2: Commit**

```bash
git add src/cli.rs && git commit -m "feat: add seal, open, verify CLI commands" && git push
```

---

## Phase 6: Polish

### Task 29: FORMAT.md

**Depends on:** T15, T16
**Files:**
- Create: `FORMAT.md`

Write a byte-level format specification documenting:
1. Magic bytes (`TOMB\n`)
2. Public header layout (version, KDF chain, layer chain, salt, commitment, header length)
3. Per-layer envelope layout (layer ID, nonce length, nonce, payload length, payload, HMAC tag)
4. Inner header layout (filename, original size, checksum, timestamp, version, note)
5. ID reference table (KDF IDs: 0x10, 0x11; Cipher IDs: 0x20, 0x21, 0x22)

**Commit:**

```bash
git add FORMAT.md && git commit -m "docs: add byte-level format specification" && git push
```

---

### Task 30: Integration Tests

**Depends on:** T28
**Files:**
- Create: `tests/integration.rs`

**Step 1: Write full integration tests**

```rust
use std::path::PathBuf;
use tomb::key::Passphrase;
use tomb::key::derive::{ScryptDerive, Argon2idDerive};

fn test_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tomb_integration_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn full_seal_open_cycle() {
    let dir = test_dir();
    let input = dir.join("secret.json");
    let output = dir.join("backup.tomb");

    let content = b"{\"key\": \"value\", \"secret\": 42}";
    std::fs::write(&input, content).unwrap();

    let passphrase = Passphrase::new(b"test passphrase for integration".to_vec());

    tomb::seal_with_params(&input, &output, &passphrase, Some("integration test")).unwrap();
    assert!(output.exists());

    let opened = tomb::open_file_with_params(
        &output,
        &passphrase,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    ).unwrap();

    assert_eq!(opened.data, content);
    assert_eq!(opened.filename, "secret.json");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn wrong_passphrase_fails() {
    let dir = test_dir();
    let input = dir.join("data.bin");
    let output = dir.join("data.tomb");

    std::fs::write(&input, b"secret data").unwrap();

    let passphrase = Passphrase::new(b"correct passphrase".to_vec());
    tomb::seal_with_params(&input, &output, &passphrase, None).unwrap();

    let wrong = Passphrase::new(b"wrong passphrase".to_vec());
    let result = tomb::open_file_with_params(
        &output,
        &wrong,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    );
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inspect_without_passphrase() {
    let dir = test_dir();
    let input = dir.join("file.txt");
    let output = dir.join("file.tomb");

    std::fs::write(&input, b"hello").unwrap();
    let passphrase = Passphrase::new(b"test".to_vec());
    tomb::seal_with_params(&input, &output, &passphrase, None).unwrap();

    let header = tomb::inspect_file(&output).unwrap();
    assert_eq!(header.version_major, 1);
    assert_eq!(header.kdf_chain.len(), 2);
    assert_eq!(header.layers.len(), 3);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn tampered_file_fails() {
    let dir = test_dir();
    let input = dir.join("data.txt");
    let output = dir.join("data.tomb");

    std::fs::write(&input, b"important data").unwrap();
    let passphrase = Passphrase::new(b"test passphrase".to_vec());
    tomb::seal_with_params(&input, &output, &passphrase, None).unwrap();

    // Tamper with the sealed file
    let mut data = std::fs::read(&output).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    std::fs::write(&output, &data).unwrap();

    let result = tomb::open_file_with_params(
        &output,
        &passphrase,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    );
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn large_file_round_trip() {
    let dir = test_dir();
    let input = dir.join("large.bin");
    let output = dir.join("large.tomb");

    // 1MB of random-ish data
    let content: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    std::fs::write(&input, &content).unwrap();

    let passphrase = Passphrase::new(b"large file test".to_vec());
    tomb::seal_with_params(&input, &output, &passphrase, None).unwrap();

    let opened = tomb::open_file_with_params(
        &output,
        &passphrase,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    ).unwrap();

    assert_eq!(opened.data, content);

    std::fs::remove_dir_all(&dir).ok();
}
```

Run: `cargo test --test integration` -- expect PASS

**Step 2: Commit**

```bash
git add tests/ && git commit -m "test: add full integration tests" && git push
```

---

### Task 31: Vendor Deps + Build Config

**Depends on:** T30
**Files:**
- Create: `.cargo/config.toml`
- Run: `cargo vendor`

**Step 1: Vendor dependencies**

```bash
cargo vendor
```

**Step 2: Create `.cargo/config.toml`**

```toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

**Step 3: Add .gitignore for build artifacts**

```
/target
```

**Step 4: Verify vendored build**

```bash
cargo build --release
```

**Step 5: Commit**

```bash
git add .cargo/ vendor/ .gitignore Cargo.lock && git commit -m "chore: vendor all dependencies" && git push
```

---

## Summary

| Phase | Tasks | Agents | Depends On |
|-------|-------|--------|------------|
| 1. Foundation | T1-T3 | 1 (sequential) | Nothing |
| 2. Core | T4-T19 | 4 (parallel) | Phase 1 |
| 3. Pipeline | T20-T21 | 1 | Streams A, C |
| 4. Library API | T22-T25 | 1 | Phase 2, 3 |
| 5. CLI | T26-T28 | 1 | Phase 4, Stream D |
| 6. Polish | T29-T31 | 1 | Phase 5 |

**Total: 31 tasks across 6 phases.**

Phase 2 is the parallelism sweet spot: 4 independent streams (ciphers, KDFs, format, passphrase) can run simultaneously after foundation is in place.
