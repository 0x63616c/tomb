pub mod envelope;

use std::collections::HashSet;

use zeroize::Zeroize;

use crate::cipher::aes::AesCtr;
use crate::cipher::lookup::cipher_by_id;
use crate::cipher::twofish::TwofishCtr;
use crate::cipher::xchacha::XChaCha;
use crate::cipher::{CipherId, CipherLayer};
use crate::format::{LayerDescriptor, PublicHeader};
use crate::key::expand::{LayerInfo, LayerState};
use crate::pipeline::envelope::LayerEnvelope;
use crate::{Error, Result};

pub struct Pipeline {
    pub(crate) layers: Vec<Box<dyn CipherLayer>>,
}

impl Pipeline {
    pub fn default_tomb() -> Self {
        let layers: Vec<Box<dyn CipherLayer>> =
            vec![Box::new(TwofishCtr), Box::new(AesCtr), Box::new(XChaCha)];
        validate_no_duplicate_ids(&layers).expect("default pipeline has no duplicate IDs");
        Self { layers }
    }

    pub fn layer_descriptors(&self) -> Vec<LayerDescriptor> {
        self.layers
            .iter()
            .map(|l| LayerDescriptor {
                id: l.id(),
                nonce_size: l.nonce_size() as u8,
            })
            .collect()
    }

    pub fn layer_info(&self) -> Vec<LayerInfo> {
        self.layers
            .iter()
            .map(|l| LayerInfo {
                encrypt_label: l.encrypt_label(),
                mac_label: l.mac_label(),
                nonce_size: l.nonce_size(),
            })
            .collect()
    }

    pub fn seal(&self, states: &[LayerState], plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.layers.len() != states.len() {
            return Err(Error::Encryption(format!(
                "layer count ({}) must match state count ({})",
                self.layers.len(),
                states.len()
            )));
        }
        let mut data = plaintext.to_vec();

        for (layer, state) in self.layers.iter().zip(states.iter()) {
            let encrypted = layer.encrypt(&state.encrypt_key, &state.nonce, &data)?;
            data.zeroize();
            let mac =
                LayerEnvelope::compute_mac(&state.mac_key, layer.id(), &state.nonce, &encrypted);
            data = LayerEnvelope {
                layer_id: layer.id(),
                nonce: state.nonce.clone(),
                payload: encrypted,
                mac,
            }
            .serialize();
        }

        Ok(data)
    }

    pub fn open(&self, states: &[LayerState], sealed: &[u8]) -> Result<Vec<u8>> {
        if self.layers.len() != states.len() {
            return Err(Error::Encryption(format!(
                "layer count ({}) must match state count ({})",
                self.layers.len(),
                states.len()
            )));
        }
        let mut data = sealed.to_vec();

        for (layer, state) in self.layers.iter().zip(states.iter()).rev() {
            let env = LayerEnvelope::deserialize(&data)?;

            if !env.verify_mac(&state.mac_key) {
                data.zeroize();
                return Err(Error::DecryptionFailed);
            }

            let decrypted = layer.decrypt(&state.encrypt_key, &env.nonce, &env.payload)?;
            data.zeroize();
            data = decrypted;
        }

        Ok(data)
    }

    pub fn from_cipher_ids(ids: &[CipherId]) -> Result<Self> {
        let layers: Vec<Box<dyn CipherLayer>> = ids.iter().map(|id| cipher_by_id(*id)).collect();
        validate_no_duplicate_ids(&layers)?;
        Ok(Self { layers })
    }

    pub fn build_from_header(header: &PublicHeader) -> Result<Self> {
        let layers: Vec<Box<dyn CipherLayer>> = header
            .layers
            .iter()
            .map(|desc| cipher_by_id(desc.id))
            .collect();
        validate_no_duplicate_ids(&layers)?;
        Ok(Self { layers })
    }
}

fn validate_no_duplicate_ids(layers: &[Box<dyn CipherLayer>]) -> Result<()> {
    let mut seen = HashSet::new();
    for layer in layers {
        if !seen.insert(layer.id()) {
            return Err(Error::Format(format!(
                "duplicate cipher layer: {:?}",
                layer.id()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::PublicHeader;
    use crate::key::expand::{expand_layer_keys, LayerInfo, LayerState};
    use crate::key::MasterKey;

    fn test_states() -> Vec<LayerState> {
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
        expand_layer_keys(&master, &layer_info).unwrap()
    }

    #[test]
    fn pipeline_seal_produces_output() {
        let pipeline = Pipeline::default_tomb();
        let states = test_states();
        let plaintext = b"hello tomb pipeline test";
        let sealed = pipeline.seal(&states, plaintext).unwrap();
        assert!(!sealed.is_empty());
        assert_ne!(&sealed, plaintext);
    }

    #[test]
    fn pipeline_seal_then_open_round_trip() {
        let pipeline = Pipeline::default_tomb();
        let states = test_states();
        let plaintext = b"round trip test data for tomb pipeline!!";
        let sealed = pipeline.seal(&states, plaintext).unwrap();
        let opened = pipeline.open(&states, &sealed).unwrap();
        assert_eq!(&opened, plaintext);
    }

    #[test]
    fn pipeline_descriptors() {
        let pipeline = Pipeline::default_tomb();
        let descs = pipeline.layer_descriptors();
        assert_eq!(descs.len(), 3);
        assert_eq!(descs[0].id, CipherId::Twofish);
        assert_eq!(descs[1].id, CipherId::Aes);
        assert_eq!(descs[2].id, CipherId::XChaCha);
    }

    #[test]
    fn pipeline_tampered_data_fails() {
        let pipeline = Pipeline::default_tomb();
        let states = test_states();
        let plaintext = b"tamper detection test";
        let mut sealed = pipeline.seal(&states, plaintext).unwrap();
        let mid = sealed.len() / 2;
        sealed[mid] ^= 0xFF;
        assert!(pipeline.open(&states, &sealed).is_err());
    }

    #[test]
    fn pipeline_build_from_header() {
        let pipeline = Pipeline::default_tomb();
        let header = PublicHeader {
            version_major: 1,
            version_minor: 0,
            kdf_chain: vec![],
            layers: pipeline.layer_descriptors(),
            salt: vec![0; 32],
            commitment: vec![0; 32],
        };
        let rebuilt = Pipeline::build_from_header(&header).unwrap();
        assert_eq!(rebuilt.layers.len(), 3);
        assert_eq!(rebuilt.layers[0].id(), CipherId::Twofish);
        assert_eq!(rebuilt.layers[1].id(), CipherId::Aes);
        assert_eq!(rebuilt.layers[2].id(), CipherId::XChaCha);
    }

    #[test]
    fn pipeline_duplicate_layer_ids_rejected() {
        let header = PublicHeader {
            version_major: 1,
            version_minor: 0,
            kdf_chain: vec![],
            layers: vec![
                LayerDescriptor {
                    id: CipherId::Twofish,
                    nonce_size: 16,
                },
                LayerDescriptor {
                    id: CipherId::Twofish,
                    nonce_size: 16,
                },
            ],
            salt: vec![0; 32],
            commitment: vec![0; 32],
        };
        let err = Pipeline::build_from_header(&header)
            .err()
            .expect("should fail");
        assert!(format!("{err}").contains("duplicate cipher layer"));
    }

    #[test]
    fn pipeline_layer_info() {
        let pipeline = Pipeline::default_tomb();
        let info = pipeline.layer_info();
        assert_eq!(info.len(), 3);
        assert_eq!(info[0].encrypt_label, "tomb-twofish-256-ctr");
        assert_eq!(info[1].encrypt_label, "tomb-aes-256-ctr");
        assert_eq!(info[2].encrypt_label, "tomb-xchacha20");
    }
}
