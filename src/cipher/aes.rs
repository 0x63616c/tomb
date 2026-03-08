use crate::cipher::{CipherId, CipherLayer};
use crate::key::LayerKey;
use crate::Result;

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};

type Aes256CtrMode = ctr::Ctr128BE<Aes256>;

pub struct AesCtr;

impl CipherLayer for AesCtr {
    fn id(&self) -> CipherId {
        CipherId::Aes
    }
    fn name(&self) -> &str {
        "aes-256-ctr"
    }
    fn encrypt_label(&self) -> &'static str {
        "tomb-aes-256-ctr"
    }
    fn mac_label(&self) -> &'static str {
        "tomb-aes-256-ctr-mac"
    }
    fn key_size(&self) -> usize {
        32
    }
    fn nonce_size(&self) -> usize {
        16
    }

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
        assert_ne!(&encrypted[..], plaintext);

        let decrypted = cipher.decrypt(&key, &nonce, &encrypted).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn aes_metadata() {
        let c = AesCtr;
        assert_eq!(c.id(), CipherId::Aes);
        assert_eq!(c.key_size(), 32);
        assert_eq!(c.nonce_size(), 16);
    }
}
