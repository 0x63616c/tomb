use crate::key::MasterKey;
use crate::{Error, Result};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

pub trait Derive {
    fn id(&self) -> u8;
    fn derive(&self, input: &[u8], salt: &[u8]) -> Result<MasterKey>;
}

// ── Scrypt ──────────────────────────────────────────────────────────────

pub struct ScryptDerive {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

impl ScryptDerive {
    pub fn production() -> Self {
        Self { log_n: 20, r: 8, p: 1 }
    }

    pub fn test() -> Self {
        Self { log_n: 10, r: 8, p: 1 }
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

// ── Argon2id ────────────────────────────────────────────────────────────

pub struct Argon2idDerive {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2idDerive {
    pub fn production() -> Self {
        Self { memory_kib: 1_048_576, iterations: 4, parallelism: 4 }
    }

    pub fn test() -> Self {
        Self { memory_kib: 1024, iterations: 1, parallelism: 1 }
    }
}

impl Derive for Argon2idDerive {
    fn id(&self) -> u8 { 0x11 }

    fn derive(&self, input: &[u8], salt: &[u8]) -> Result<MasterKey> {
        let params = argon2::Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|e| Error::Encryption(format!("argon2 params: {e}")))?;
        let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut output = [0u8; 32];
        argon2.hash_password_into(input, salt, &mut output)
            .map_err(|e| Error::Encryption(format!("argon2: {e}")))?;
        Ok(MasterKey(output))
    }
}

// ── Chained KDF ─────────────────────────────────────────────────────────

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
        kdf_salt.zeroize();
        input.zeroize();
        input = result.as_bytes().to_vec();
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&input);
    input.zeroize();
    Ok(MasterKey(key))
}

// ── KDF Lookup ──────────────────────────────────────────────────────────

pub fn kdf_by_id(id: u8) -> Result<Box<dyn Derive>> {
    match id {
        0x10 => Ok(Box::new(ScryptDerive::production())),
        0x11 => Ok(Box::new(Argon2idDerive::production())),
        _ => Err(Error::UnknownKdf(id)),
    }
}

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

    #[test]
    fn chain_derive_deterministic() {
        let kdfs: Vec<Box<dyn Derive>> = vec![
            Box::new(ScryptDerive::test()),
            Box::new(Argon2idDerive::test()),
        ];
        let salt = b"salt1234567890123456789012345678";
        let key1 = chain_derive(&kdfs, b"passphrase", salt).unwrap();

        let kdfs2: Vec<Box<dyn Derive>> = vec![
            Box::new(ScryptDerive::test()),
            Box::new(Argon2idDerive::test()),
        ];
        let key2 = chain_derive(&kdfs2, b"passphrase", salt).unwrap();
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

    #[test]
    fn kdf_lookup() {
        assert_eq!(kdf_by_id(0x10).unwrap().id(), 0x10);
        assert_eq!(kdf_by_id(0x11).unwrap().id(), 0x11);
        assert!(kdf_by_id(0xFF).is_err());
    }
}
