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
