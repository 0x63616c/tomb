pub mod twofish;
pub mod aes;
pub mod xchacha;
pub mod lookup;

use crate::key::LayerKey;
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

pub trait CipherLayer {
    fn id(&self) -> CipherId;
    fn name(&self) -> &str;
    fn encrypt_label(&self) -> &'static str;
    fn mac_label(&self) -> &'static str;
    fn key_size(&self) -> usize;
    fn nonce_size(&self) -> usize;
    fn encrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>>;
}

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
