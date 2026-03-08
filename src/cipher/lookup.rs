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

#[cfg(test)]
mod tests {
    use super::*;

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
}
