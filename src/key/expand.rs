use crate::key::{LayerKey, MasterKey};
use crate::{random_bytes, Error, Result};

use hkdf::Hkdf;
use sha2::Sha256;

pub struct LayerInfo {
    pub encrypt_label: &'static str,
    pub mac_label: &'static str,
    pub nonce_size: usize,
}

pub struct LayerState {
    pub encrypt_key: LayerKey,
    pub mac_key: LayerKey,
    pub nonce: Vec<u8>,
}

pub fn expand_layer_keys(master: &MasterKey, layers: &[LayerInfo]) -> Result<Vec<LayerState>> {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut states = Vec::new();

    for layer in layers {
        debug_assert!(layer.nonce_size > 0, "nonce size must be positive");

        let mut encrypt_key = [0u8; 32];
        hk.expand(layer.encrypt_label.as_bytes(), &mut encrypt_key)
            .map_err(|_| Error::KeyExpansion)?;

        let mut mac_key = [0u8; 32];
        hk.expand(layer.mac_label.as_bytes(), &mut mac_key)
            .map_err(|_| Error::KeyExpansion)?;

        let nonce = random_bytes(layer.nonce_size);

        states.push(LayerState {
            encrypt_key: LayerKey(encrypt_key),
            mac_key: LayerKey(mac_key),
            nonce,
        });
    }

    Ok(states)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_produces_correct_count() {
        let master = MasterKey([0xAA; 32]);
        let layer_info = vec![
            LayerInfo {
                encrypt_label: "tomb-twofish-256-ctr",
                mac_label: "tomb-twofish-256-ctr-mac",
                nonce_size: 16,
            },
            LayerInfo {
                encrypt_label: "tomb-aes-256-ctr",
                mac_label: "tomb-aes-256-ctr-mac",
                nonce_size: 16,
            },
            LayerInfo {
                encrypt_label: "tomb-xchacha20",
                mac_label: "tomb-xchacha20-mac",
                nonce_size: 24,
            },
        ];
        let states = expand_layer_keys(&master, &layer_info).unwrap();
        assert_eq!(states.len(), 3);
        assert_eq!(states[0].nonce.len(), 16);
        assert_eq!(states[2].nonce.len(), 24);
    }

    #[test]
    fn expand_different_keys_per_layer() {
        let master = MasterKey([0xBB; 32]);
        let layer_info = vec![
            LayerInfo {
                encrypt_label: "tomb-twofish-256-ctr",
                mac_label: "tomb-twofish-256-ctr-mac",
                nonce_size: 16,
            },
            LayerInfo {
                encrypt_label: "tomb-aes-256-ctr",
                mac_label: "tomb-aes-256-ctr-mac",
                nonce_size: 16,
            },
        ];
        let states = expand_layer_keys(&master, &layer_info).unwrap();
        assert_ne!(
            states[0].encrypt_key.as_bytes(),
            states[1].encrypt_key.as_bytes()
        );
        assert_ne!(states[0].mac_key.as_bytes(), states[1].mac_key.as_bytes());
    }

    #[test]
    fn expand_encrypt_key_differs_from_mac_key() {
        let master = MasterKey([0xCC; 32]);
        let layer_info = vec![LayerInfo {
            encrypt_label: "tomb-twofish-256-ctr",
            mac_label: "tomb-twofish-256-ctr-mac",
            nonce_size: 16,
        }];
        let states = expand_layer_keys(&master, &layer_info).unwrap();
        assert_ne!(
            states[0].encrypt_key.as_bytes(),
            states[0].mac_key.as_bytes()
        );
    }
}
