use crate::cipher::{CipherLayer, CipherId};
use crate::key::LayerKey;
use crate::Result;

use twofish::Twofish;
use ctr::cipher::{KeyIvInit, StreamCipher};

type TwofishCtrMode = ctr::Ctr128BE<Twofish>;

pub struct TwofishCtr;

impl CipherLayer for TwofishCtr {
    fn id(&self) -> CipherId { CipherId::Twofish }
    fn name(&self) -> &str { "twofish-256-ctr" }
    fn encrypt_label(&self) -> &'static str { "tomb-twofish-256-ctr" }
    fn mac_label(&self) -> &'static str { "tomb-twofish-256-ctr-mac" }
    fn key_size(&self) -> usize { 32 }
    fn nonce_size(&self) -> usize { 16 }

    fn encrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = data.to_vec();
        let mut cipher = TwofishCtrMode::new(key.as_bytes().into(), nonce.into());
        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    fn decrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(key, nonce, data)
    }
}

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
        assert_ne!(&encrypted[..], plaintext);

        let decrypted = cipher.decrypt(&key, &nonce, &encrypted).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn twofish_metadata() {
        let c = TwofishCtr;
        assert_eq!(c.id(), CipherId::Twofish);
        assert_eq!(c.key_size(), 32);
        assert_eq!(c.nonce_size(), 16);
    }
}
