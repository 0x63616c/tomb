pub mod twofish;
pub mod aes;
pub mod xchacha;
pub mod lookup;

use crate::key::LayerKey;
use crate::Result;

pub trait CipherLayer {
    fn id(&self) -> u8;
    fn name(&self) -> &str;
    fn encrypt_label(&self) -> &'static str;
    fn mac_label(&self) -> &'static str;
    fn key_size(&self) -> usize;
    fn nonce_size(&self) -> usize;
    fn encrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, key: &LayerKey, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>>;
}
