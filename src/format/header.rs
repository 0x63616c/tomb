use crate::cipher::CipherId;
use crate::key::derive::KdfParams;
use crate::{Error, Result};

pub const FORMAT_VERSION_MAJOR: u8 = 1;
pub const FORMAT_VERSION_MINOR: u8 = 0;

pub struct LayerDescriptor {
    pub id: CipherId,
    pub nonce_size: u8,
}

pub struct PublicHeader {
    pub version_major: u8,
    pub version_minor: u8,
    pub kdf_chain: Vec<KdfParams>,
    pub layers: Vec<LayerDescriptor>,
    pub salt: Vec<u8>,
    pub commitment: Vec<u8>,
}

impl PublicHeader {
    /// Serialize: [TOMB\n][ver_major:1][ver_minor:1]
    ///   [kdf_count:1][foreach: KdfParams native serialization]
    ///   [layer_count:1][foreach: id:1, nonce_size:1]
    ///   [salt:32][commitment:32]
    ///   [header_len:4 LE] (total length including this field)
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();

        out.extend_from_slice(b"TOMB\n");
        out.push(self.version_major);
        out.push(self.version_minor);

        out.push(self.kdf_chain.len() as u8);
        for kdf in &self.kdf_chain {
            out.extend_from_slice(&kdf.serialize());
        }

        out.push(self.layers.len() as u8);
        for layer in &self.layers {
            out.push(layer.id as u8);
            out.push(layer.nonce_size);
        }

        if self.salt.len() != 32 {
            return Err(Error::Format("salt must be 32 bytes".into()));
        }
        if self.commitment.len() != 32 {
            return Err(Error::Format("commitment must be 32 bytes".into()));
        }
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.commitment);

        let total_len =
            u32::try_from(out.len() + 4).map_err(|_| Error::Format("header too large".into()))?;
        out.extend_from_slice(&total_len.to_le_bytes());

        Ok(out)
    }

    pub fn deserialize(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 5 || &data[..5] != b"TOMB\n" {
            return Err(Error::Format("missing TOMB magic".into()));
        }

        let mut pos = 5;

        if pos + 2 > data.len() {
            return Err(Error::Format("truncated version".into()));
        }
        let version_major = data[pos];
        let version_minor = data[pos + 1];
        pos += 2;

        if pos >= data.len() {
            return Err(Error::Format("truncated kdf count".into()));
        }
        let kdf_count = data[pos] as usize;
        pos += 1;

        let mut kdf_chain = Vec::with_capacity(kdf_count);
        for _ in 0..kdf_count {
            if pos >= data.len() {
                return Err(Error::Format("truncated kdf params".into()));
            }
            let (params, consumed) = KdfParams::deserialize(&data[pos..])?;
            pos += consumed;
            kdf_chain.push(params);
        }

        if pos >= data.len() {
            return Err(Error::Format("truncated layer count".into()));
        }
        let layer_count = data[pos] as usize;
        pos += 1;

        let mut layers = Vec::with_capacity(layer_count);
        for _ in 0..layer_count {
            if pos + 2 > data.len() {
                return Err(Error::Format("truncated layer".into()));
            }
            let id = CipherId::try_from(data[pos])?;
            let nonce_size = data[pos + 1];
            pos += 2;
            layers.push(LayerDescriptor { id, nonce_size });
        }

        let salt_end = pos
            .checked_add(32)
            .ok_or_else(|| Error::Format("salt offset overflow".into()))?;
        let commitment_end = salt_end
            .checked_add(32)
            .ok_or_else(|| Error::Format("commitment offset overflow".into()))?;
        if commitment_end > data.len() {
            return Err(Error::Format("truncated salt/commitment".into()));
        }
        let salt = data[pos..salt_end].to_vec();
        let commitment = data[salt_end..commitment_end].to_vec();
        pos = commitment_end;

        let header_len_end = pos
            .checked_add(4)
            .ok_or_else(|| Error::Format("header length offset overflow".into()))?;
        if header_len_end > data.len() {
            return Err(Error::Format("truncated header length".into()));
        }
        let header_len = u32::from_le_bytes(data[pos..header_len_end].try_into().unwrap()) as usize;
        pos = header_len_end;

        if pos != header_len {
            return Err(Error::Format(format!(
                "header length mismatch: expected {header_len}, got {pos}"
            )));
        }

        Ok((
            Self {
                version_major,
                version_minor,
                kdf_chain,
                layers,
                salt,
                commitment,
            },
            pos,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::derive::KdfId;

    #[test]
    fn public_header_round_trip() {
        let header = PublicHeader {
            version_major: FORMAT_VERSION_MAJOR,
            version_minor: FORMAT_VERSION_MINOR,
            kdf_chain: vec![
                KdfParams::Scrypt {
                    log_n: 20,
                    r: 8,
                    p: 1,
                },
                KdfParams::Argon2id {
                    memory_kib: 1_048_576,
                    iterations: 4,
                    parallelism: 4,
                },
            ],
            layers: vec![
                LayerDescriptor {
                    id: CipherId::Twofish,
                    nonce_size: 16,
                },
                LayerDescriptor {
                    id: CipherId::Aes,
                    nonce_size: 16,
                },
                LayerDescriptor {
                    id: CipherId::XChaCha,
                    nonce_size: 24,
                },
            ],
            salt: vec![0xAA; 32],
            commitment: vec![0xBB; 32],
        };

        let bytes = header.serialize().unwrap();
        assert_eq!(&bytes[..5], b"TOMB\n");

        let (parsed, consumed) = PublicHeader::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.version_major, FORMAT_VERSION_MAJOR);
        assert_eq!(parsed.version_minor, FORMAT_VERSION_MINOR);
        assert_eq!(parsed.kdf_chain.len(), 2);
        assert_eq!(parsed.kdf_chain[0].id(), KdfId::Scrypt);
        assert_eq!(parsed.kdf_chain[1].id(), KdfId::Argon2id);
        assert_eq!(parsed.layers.len(), 3);
        assert_eq!(parsed.layers[0].id, CipherId::Twofish);
        assert_eq!(parsed.salt.len(), 32);
        assert_eq!(parsed.commitment.len(), 32);
    }

    #[test]
    fn public_header_magic_bytes() {
        let header = PublicHeader {
            version_major: FORMAT_VERSION_MAJOR,
            version_minor: FORMAT_VERSION_MINOR,
            kdf_chain: vec![],
            layers: vec![],
            salt: vec![0; 32],
            commitment: vec![0; 32],
        };
        let bytes = header.serialize().unwrap();
        assert_eq!(&bytes[..5], b"TOMB\n");
    }

    fn valid_header_bytes() -> Vec<u8> {
        let header = PublicHeader {
            version_major: FORMAT_VERSION_MAJOR,
            version_minor: FORMAT_VERSION_MINOR,
            kdf_chain: vec![
                KdfParams::Scrypt {
                    log_n: 10,
                    r: 8,
                    p: 1,
                },
                KdfParams::Argon2id {
                    memory_kib: 1024,
                    iterations: 1,
                    parallelism: 1,
                },
            ],
            layers: vec![
                LayerDescriptor {
                    id: CipherId::Twofish,
                    nonce_size: 16,
                },
                LayerDescriptor {
                    id: CipherId::Aes,
                    nonce_size: 16,
                },
                LayerDescriptor {
                    id: CipherId::XChaCha,
                    nonce_size: 24,
                },
            ],
            salt: vec![0xAA; 32],
            commitment: vec![0xBB; 32],
        };
        header.serialize().unwrap()
    }

    #[test]
    fn deserialize_empty_data() {
        assert!(PublicHeader::deserialize(&[]).is_err());
    }

    #[test]
    fn deserialize_wrong_magic() {
        let mut bytes = valid_header_bytes();
        bytes[0] = b'X';
        assert!(PublicHeader::deserialize(&bytes).is_err());
    }

    #[test]
    fn deserialize_truncated_after_magic() {
        assert!(PublicHeader::deserialize(b"TOMB\n").is_err());
    }

    #[test]
    fn deserialize_truncated_after_version() {
        assert!(PublicHeader::deserialize(b"TOMB\n\x01\x00").is_err());
    }

    #[test]
    fn deserialize_truncated_kdf_params() {
        // Magic + version + kdf_count=2, but no KDF data
        let data = b"TOMB\n\x01\x00\x02";
        assert!(PublicHeader::deserialize(data).is_err());
    }

    #[test]
    fn deserialize_truncated_layer_data() {
        let bytes = valid_header_bytes();
        // Find where layers start: after magic(5) + version(2) + kdf_count(1) + kdf_data + layer_count(1)
        // Truncate right after layer_count byte, cutting off actual layer descriptors
        let (header, _) = PublicHeader::deserialize(&bytes).unwrap();
        // Rebuild with just enough to get past KDFs but truncate layers
        let mut partial = Vec::new();
        partial.extend_from_slice(b"TOMB\n");
        partial.push(header.version_major);
        partial.push(header.version_minor);
        partial.push(0); // 0 KDFs
        partial.push(3); // 3 layers, but no layer data follows
        assert!(PublicHeader::deserialize(&partial).is_err());
    }

    #[test]
    fn deserialize_truncated_salt() {
        // Valid up to layers, but missing salt/commitment
        let mut partial = Vec::new();
        partial.extend_from_slice(b"TOMB\n");
        partial.push(1);
        partial.push(0);
        partial.push(0); // 0 KDFs
        partial.push(0); // 0 layers
                         // Missing salt and commitment
        assert!(PublicHeader::deserialize(&partial).is_err());
    }

    #[test]
    fn deserialize_invalid_cipher_id() {
        let mut partial = Vec::new();
        partial.extend_from_slice(b"TOMB\n");
        partial.push(1);
        partial.push(0);
        partial.push(0); // 0 KDFs
        partial.push(1); // 1 layer
        partial.push(0xFF); // invalid cipher ID
        partial.push(16); // nonce_size
        partial.extend_from_slice(&[0; 32]); // salt
        partial.extend_from_slice(&[0; 32]); // commitment
        let total_len = (partial.len() + 4) as u32;
        partial.extend_from_slice(&total_len.to_le_bytes());
        assert!(PublicHeader::deserialize(&partial).is_err());
    }

    #[test]
    fn deserialize_header_length_mismatch() {
        let mut bytes = valid_header_bytes();
        // Corrupt the header_len field (last 4 bytes) to a wrong value
        let len = bytes.len();
        bytes[len - 4..].copy_from_slice(&999u32.to_le_bytes());
        match PublicHeader::deserialize(&bytes) {
            Err(e) => assert!(format!("{e}").contains("header length mismatch")),
            Ok(_) => panic!("expected error"),
        }
    }
}
