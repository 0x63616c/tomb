use crate::key::MasterKey;
use crate::{Error, Result};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KdfId {
    Scrypt = 0x01,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfParams {
    Scrypt {
        log_n: u8,
        r: u32,
        p: u32,
    },
    Argon2id {
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    },
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
            KdfParams::Scrypt { log_n, r, p } => Box::new(ScryptDerive {
                log_n: *log_n,
                r: *r,
                p: *p,
            }),
            KdfParams::Argon2id {
                memory_kib,
                iterations,
                parallelism,
            } => Box::new(Argon2idDerive {
                memory_kib: *memory_kib,
                iterations: *iterations,
                parallelism: *parallelism,
            }),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            KdfParams::Scrypt { log_n, r, p } => {
                out.push(KdfId::Scrypt as u8);
                out.push(*log_n);
                out.extend_from_slice(&r.to_le_bytes());
                out.extend_from_slice(&p.to_le_bytes());
            }
            KdfParams::Argon2id {
                memory_kib,
                iterations,
                parallelism,
            } => {
                out.push(KdfId::Argon2id as u8);
                out.extend_from_slice(&memory_kib.to_le_bytes());
                out.extend_from_slice(&iterations.to_le_bytes());
                out.extend_from_slice(&parallelism.to_le_bytes());
            }
        }
        out
    }

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
                Ok((
                    KdfParams::Argon2id {
                        memory_kib,
                        iterations,
                        parallelism,
                    },
                    13,
                ))
            }
        }
    }

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

pub trait Derive {
    fn id(&self) -> KdfId;
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
        Self {
            log_n: 20,
            r: 8,
            p: 1,
        }
    }

    pub fn test() -> Self {
        Self {
            log_n: 10,
            r: 8,
            p: 1,
        }
    }
}

impl Derive for ScryptDerive {
    fn id(&self) -> KdfId {
        KdfId::Scrypt
    }

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
        Self {
            memory_kib: 1_048_576,
            iterations: 4,
            parallelism: 4,
        }
    }

    pub fn test() -> Self {
        Self {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        }
    }
}

impl Derive for Argon2idDerive {
    fn id(&self) -> KdfId {
        KdfId::Argon2id
    }

    fn derive(&self, input: &[u8], salt: &[u8]) -> Result<MasterKey> {
        let params =
            argon2::Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
                .map_err(|e| Error::Encryption(format!("argon2 params: {e}")))?;
        let argon2 =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut output = [0u8; 32];
        argon2
            .hash_password_into(input, salt, &mut output)
            .map_err(|e| Error::Encryption(format!("argon2: {e}")))?;
        Ok(MasterKey(output))
    }
}

// ── Chained KDF ─────────────────────────────────────────────────────────

pub fn chain_derive(kdfs: &[Box<dyn Derive>], passphrase: &[u8], salt: &[u8]) -> Result<MasterKey> {
    let prk = Hkdf::<Sha256>::new(None, salt);
    let mut input = passphrase.to_vec();

    for kdf in kdfs {
        let label = format!("tomb-kdf-{:02x}-salt", kdf.id() as u8);
        let mut kdf_salt = vec![0u8; 32];
        prk.expand(label.as_bytes(), &mut kdf_salt)
            .map_err(|_| Error::KeyExpansion)?;
        let result = kdf.derive(&input, &kdf_salt)?;
        kdf_salt.zeroize();
        input.zeroize();
        input = result.as_bytes().to_vec();
    }

    assert_eq!(input.len(), 32, "KDF chain must produce 32-byte key");
    let mut key = [0u8; 32];
    key.copy_from_slice(&input);
    input.zeroize();
    Ok(MasterKey(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrypt_derive_deterministic() {
        let kdf = ScryptDerive::test();
        let key1 = kdf
            .derive(b"passphrase", b"salt1234567890123456789012345678")
            .unwrap();
        let key2 = kdf
            .derive(b"passphrase", b"salt1234567890123456789012345678")
            .unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn scrypt_derive_different_input_different_output() {
        let kdf = ScryptDerive::test();
        let key1 = kdf
            .derive(b"passphrase1", b"salt1234567890123456789012345678")
            .unwrap();
        let key2 = kdf
            .derive(b"passphrase2", b"salt1234567890123456789012345678")
            .unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn scrypt_metadata() {
        let kdf = ScryptDerive::test();
        assert_eq!(kdf.id(), KdfId::Scrypt);
    }

    #[test]
    fn argon2id_derive_deterministic() {
        let kdf = Argon2idDerive::test();
        let key1 = kdf
            .derive(b"passphrase", b"salt5678901234567890123456789012")
            .unwrap();
        let key2 = kdf
            .derive(b"passphrase", b"salt5678901234567890123456789012")
            .unwrap();
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
        assert_eq!(kdf.id(), KdfId::Argon2id);
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

    #[test]
    fn kdf_params_scrypt_id() {
        let params = KdfParams::Scrypt {
            log_n: 20,
            r: 8,
            p: 1,
        };
        assert_eq!(params.id(), KdfId::Scrypt);
    }

    #[test]
    fn kdf_params_argon2id_id() {
        let params = KdfParams::Argon2id {
            memory_kib: 1_048_576,
            iterations: 4,
            parallelism: 4,
        };
        assert_eq!(params.id(), KdfId::Argon2id);
    }

    #[test]
    fn kdf_params_scrypt_serialize_round_trip() {
        let params = KdfParams::Scrypt {
            log_n: 20,
            r: 8,
            p: 1,
        };
        let bytes = params.serialize();
        assert_eq!(bytes[0], KdfId::Scrypt as u8);
        let (parsed, consumed) = KdfParams::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, params);
    }

    #[test]
    fn kdf_params_argon2id_serialize_round_trip() {
        let params = KdfParams::Argon2id {
            memory_kib: 1_048_576,
            iterations: 4,
            parallelism: 4,
        };
        let bytes = params.serialize();
        assert_eq!(bytes[0], KdfId::Argon2id as u8);
        let (parsed, consumed) = KdfParams::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, params);
    }

    #[test]
    fn kdf_params_to_derive_scrypt() {
        let params = KdfParams::Scrypt {
            log_n: 10,
            r: 8,
            p: 1,
        };
        let d = params.to_derive();
        assert_eq!(d.id(), KdfId::Scrypt);
        let result = d.derive(b"test", b"salt1234567890123456789012345678");
        assert!(result.is_ok());
    }

    #[test]
    fn kdf_params_to_derive_argon2id() {
        let params = KdfParams::Argon2id {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let d = params.to_derive();
        assert_eq!(d.id(), KdfId::Argon2id);
        let result = d.derive(b"test", b"salt5678901234567890123456789012");
        assert!(result.is_ok());
    }

    #[test]
    fn kdf_params_memory_display_scrypt() {
        let params = KdfParams::Scrypt {
            log_n: 20,
            r: 8,
            p: 1,
        };
        assert_eq!(params.memory_display(), "1024MB");
    }

    #[test]
    fn kdf_params_memory_display_argon2id() {
        let params = KdfParams::Argon2id {
            memory_kib: 1_048_576,
            iterations: 4,
            parallelism: 4,
        };
        assert_eq!(params.memory_display(), "1024MB");
    }

    #[test]
    fn kdf_params_deserialize_empty() {
        assert!(KdfParams::deserialize(&[]).is_err());
    }

    #[test]
    fn kdf_params_deserialize_unknown_id() {
        assert!(KdfParams::deserialize(&[0xFF]).is_err());
    }

    #[test]
    fn kdf_params_deserialize_truncated_scrypt() {
        // Scrypt ID but only 5 bytes (needs 10)
        let data = [KdfId::Scrypt as u8, 10, 0, 0, 0];
        assert!(KdfParams::deserialize(&data).is_err());
    }

    #[test]
    fn kdf_params_deserialize_truncated_argon2id() {
        // Argon2id ID but only 5 bytes (needs 13)
        let data = [KdfId::Argon2id as u8, 0, 0, 0, 0];
        assert!(KdfParams::deserialize(&data).is_err());
    }
}
