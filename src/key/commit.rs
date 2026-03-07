use crate::key::{MasterKey, Commitment};

use hmac::{Hmac, Mac};
use sha2::Sha256;

const COMMITMENT_LABEL: &[u8] = b"tomb-key-commitment";

pub fn compute_commitment(master: &MasterKey) -> Commitment {
    let mut mac = Hmac::<Sha256>::new_from_slice(master.as_bytes())
        .expect("HMAC key size is always valid");
    mac.update(COMMITMENT_LABEL);
    let result = mac.finalize().into_bytes();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Commitment(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_deterministic() {
        let master = MasterKey([0xDD; 32]);
        let c1 = compute_commitment(&master);
        let c2 = compute_commitment(&master);
        assert!(c1.verify(&c2));
    }

    #[test]
    fn commitment_different_keys_different_output() {
        let m1 = MasterKey([0x01; 32]);
        let m2 = MasterKey([0x02; 32]);
        let c1 = compute_commitment(&m1);
        let c2 = compute_commitment(&m2);
        assert!(!c1.verify(&c2));
    }
}
