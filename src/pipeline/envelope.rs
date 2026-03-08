use crate::cipher::CipherId;
use crate::key::LayerKey;
use crate::{Error, Result};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub struct LayerEnvelope {
    pub layer_id: CipherId,
    pub nonce: Vec<u8>,
    pub payload: Vec<u8>,
    pub mac: [u8; 32],
}

impl LayerEnvelope {
    /// Serialize: [layer_id:1][nonce_len:1][nonce:N][payload_len:8 LE][payload:M][mac:32]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.layer_id as u8);
        out.push(self.nonce.len() as u8);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.mac);
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::Format("envelope too short".into()));
        }

        let layer_id = CipherId::try_from(data[0])?;
        let nonce_len = data[1] as usize;

        let payload_len_start = 2usize
            .checked_add(nonce_len)
            .ok_or_else(|| Error::Format("nonce length overflow".into()))?;
        let payload_len_end = payload_len_start
            .checked_add(8)
            .ok_or_else(|| Error::Format("payload length overflow".into()))?;

        if data.len() < payload_len_end {
            return Err(Error::Format("truncated envelope header".into()));
        }

        let nonce = data[2..payload_len_start].to_vec();
        let payload_len_u64 =
            u64::from_le_bytes(data[payload_len_start..payload_len_end].try_into().unwrap());
        let payload_len: usize = payload_len_u64
            .try_into()
            .map_err(|_| Error::Format("payload length exceeds platform address space".into()))?;

        let payload_start = payload_len_end;
        let payload_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| Error::Format("payload size overflow".into()))?;
        let mac_end = payload_end
            .checked_add(32)
            .ok_or_else(|| Error::Format("mac offset overflow".into()))?;

        if data.len() < mac_end {
            return Err(Error::Format("truncated envelope body".into()));
        }

        let payload = data[payload_start..payload_end].to_vec();
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[payload_end..mac_end]);

        Ok(Self {
            layer_id,
            nonce,
            payload,
            mac,
        })
    }

    /// Compute HMAC-SHA256 over [layer_id || nonce || payload]
    pub fn compute_mac(
        mac_key: &LayerKey,
        layer_id: CipherId,
        nonce: &[u8],
        payload: &[u8],
    ) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(mac_key.as_bytes())
            .expect("HMAC key size is always valid");
        mac.update(&[layer_id as u8]);
        mac.update(nonce);
        mac.update(payload);
        let result = mac.finalize().into_bytes();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }

    /// Verify HMAC tag (constant-time)
    pub fn verify_mac(&self, mac_key: &LayerKey) -> bool {
        let expected = Self::compute_mac(mac_key, self.layer_id, &self.nonce, &self.payload);
        bool::from(self.mac.ct_eq(&expected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::LayerKey;

    #[test]
    fn envelope_round_trip() {
        let mac_key = LayerKey([0xDD; 32]);
        let nonce = vec![1u8; 16];
        let payload = vec![2u8; 100];
        let mac = LayerEnvelope::compute_mac(&mac_key, CipherId::Twofish, &nonce, &payload);

        let env = LayerEnvelope {
            layer_id: CipherId::Twofish,
            nonce: nonce.clone(),
            payload: payload.clone(),
            mac,
        };

        let bytes = env.serialize();
        let parsed = LayerEnvelope::deserialize(&bytes).unwrap();

        assert_eq!(parsed.layer_id, CipherId::Twofish);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.mac, mac);
    }

    #[test]
    fn envelope_mac_verification_passes() {
        let mac_key = LayerKey([0xEE; 32]);
        let nonce = vec![3u8; 24];
        let payload = vec![4u8; 50];
        let mac = LayerEnvelope::compute_mac(&mac_key, CipherId::XChaCha, &nonce, &payload);

        let env = LayerEnvelope {
            layer_id: CipherId::XChaCha,
            nonce,
            payload,
            mac,
        };
        assert!(env.verify_mac(&mac_key));
    }

    #[test]
    fn envelope_tampered_payload_fails_mac() {
        let mac_key = LayerKey([0xFF; 32]);
        let nonce = vec![5u8; 16];
        let payload = vec![6u8; 50];
        let mac = LayerEnvelope::compute_mac(&mac_key, CipherId::Aes, &nonce, &payload);

        let mut tampered_payload = payload;
        tampered_payload[0] ^= 0xFF;

        let env = LayerEnvelope {
            layer_id: CipherId::Aes,
            nonce,
            payload: tampered_payload,
            mac,
        };
        assert!(!env.verify_mac(&mac_key));
    }

    #[test]
    fn envelope_wrong_key_fails_mac() {
        let mac_key = LayerKey([0xAA; 32]);
        let wrong_key = LayerKey([0xBB; 32]);
        let nonce = vec![7u8; 16];
        let payload = vec![8u8; 50];
        let mac = LayerEnvelope::compute_mac(&mac_key, CipherId::Twofish, &nonce, &payload);

        let env = LayerEnvelope {
            layer_id: CipherId::Twofish,
            nonce,
            payload,
            mac,
        };
        assert!(!env.verify_mac(&wrong_key));
    }

    #[test]
    fn deserialize_empty() {
        assert!(LayerEnvelope::deserialize(&[]).is_err());
    }

    #[test]
    fn deserialize_single_byte() {
        assert!(LayerEnvelope::deserialize(&[0x01]).is_err());
    }

    #[test]
    fn deserialize_invalid_cipher_id() {
        let data = [0xFF, 0x10]; // invalid cipher ID, nonce_len=16
        assert!(LayerEnvelope::deserialize(&data).is_err());
    }

    #[test]
    fn deserialize_truncated_nonce() {
        // Valid cipher ID and nonce_len=16, but only 2 bytes of nonce
        let mut data = vec![CipherId::Aes as u8, 16];
        data.extend_from_slice(&[0u8; 2]); // only 2 of 16 nonce bytes
        assert!(LayerEnvelope::deserialize(&data).is_err());
    }

    #[test]
    fn deserialize_truncated_payload() {
        // Valid header but payload is shorter than declared length
        let mac_key = LayerKey([0xCC; 32]);
        let nonce = vec![0u8; 16];
        let payload = vec![0u8; 100];
        let mac = LayerEnvelope::compute_mac(&mac_key, CipherId::Twofish, &nonce, &payload);
        let env = LayerEnvelope {
            layer_id: CipherId::Twofish,
            nonce,
            payload,
            mac,
        };
        let bytes = env.serialize();
        // Truncate: cut off last 50 bytes (part of payload + mac)
        let truncated = &bytes[..bytes.len() - 50];
        assert!(LayerEnvelope::deserialize(truncated).is_err());
    }
}
