use crate::cipher::{CipherId, CipherLayer};
use crate::key::LayerKey;
use crate::Result;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::XChaCha20 as XChaCha20Cipher;

pub struct XChaCha;

impl CipherLayer for XChaCha {
    fn id(&self) -> CipherId {
        CipherId::XChaCha
    }
    fn name(&self) -> &str {
        "xchacha20"
    }
    fn encrypt_label(&self) -> &'static str {
        "tomb-xchacha20"
    }
    fn mac_label(&self) -> &'static str {
        "tomb-xchacha20-mac"
    }
    fn key_size(&self) -> usize {
        32
    }
    fn nonce_size(&self) -> usize {
        24
    }

    fn encrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 24 {
            return Err(crate::Error::Encryption(format!(
                "XChaCha20 nonce must be 24 bytes, got {}",
                nonce.len()
            )));
        }
        let mut buffer = data.to_vec();
        let mut cipher = XChaCha20Cipher::new(key.as_bytes().into(), nonce.into());
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
    fn xchacha_round_trip() {
        let key = LayerKey([0xCC; 32]);
        let nonce = [0u8; 24];
        let plaintext = b"hello tomb xchacha test data!!!!";

        let cipher = XChaCha;
        let encrypted = cipher.encrypt(&key, &nonce, plaintext).unwrap();
        assert_ne!(&encrypted[..], plaintext);

        let decrypted = cipher.decrypt(&key, &nonce, &encrypted).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn xchacha_metadata() {
        let c = XChaCha;
        assert_eq!(c.id(), CipherId::XChaCha);
        assert_eq!(c.key_size(), 32);
        assert_eq!(c.nonce_size(), 24);
    }
}
