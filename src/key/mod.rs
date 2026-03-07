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

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn verify(&self, other: &Commitment) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

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
        let p = Passphrase(b"hello world".to_vec());
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
