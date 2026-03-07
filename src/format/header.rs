use crate::{Error, Result};

pub struct KdfDescriptor {
    pub id: u8,
    pub memory_mb: u32,
    pub iterations: u32,
    pub parallelism: u8,
}

pub struct LayerDescriptor {
    pub id: u8,
    pub nonce_size: u8,
}

pub struct PublicHeader {
    pub version_major: u8,
    pub version_minor: u8,
    pub kdf_chain: Vec<KdfDescriptor>,
    pub layers: Vec<LayerDescriptor>,
    pub salt: Vec<u8>,
    pub commitment: Vec<u8>,
}

impl PublicHeader {
    /// Serialize: [TOMB\n][ver_major:1][ver_minor:1]
    ///   [kdf_count:1][foreach: id:1, memory_mb:4 LE, iterations:4 LE, parallelism:1]
    ///   [layer_count:1][foreach: id:1, nonce_size:1]
    ///   [salt:32][commitment:32]
    ///   [header_len:4 LE] (total length including this field)
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        out.extend_from_slice(b"TOMB\n");
        out.push(self.version_major);
        out.push(self.version_minor);

        out.push(self.kdf_chain.len() as u8);
        for kdf in &self.kdf_chain {
            out.push(kdf.id);
            out.extend_from_slice(&kdf.memory_mb.to_le_bytes());
            out.extend_from_slice(&kdf.iterations.to_le_bytes());
            out.push(kdf.parallelism);
        }

        out.push(self.layers.len() as u8);
        for layer in &self.layers {
            out.push(layer.id);
            out.push(layer.nonce_size);
        }

        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.commitment);

        let total_len = (out.len() + 4) as u32;
        out.extend_from_slice(&total_len.to_le_bytes());

        out
    }

    pub fn deserialize(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 5 || &data[..5] != b"TOMB\n" {
            return Err(Error::Format("missing TOMB magic".into()));
        }

        let mut pos = 5;

        if pos + 2 > data.len() { return Err(Error::Format("truncated version".into())); }
        let version_major = data[pos];
        let version_minor = data[pos + 1];
        pos += 2;

        if pos >= data.len() { return Err(Error::Format("truncated kdf count".into())); }
        let kdf_count = data[pos] as usize;
        pos += 1;

        let mut kdf_chain = Vec::with_capacity(kdf_count);
        for _ in 0..kdf_count {
            if pos + 10 > data.len() { return Err(Error::Format("truncated kdf".into())); }
            let id = data[pos];
            let memory_mb = u32::from_le_bytes(data[pos + 1..pos + 5].try_into().unwrap());
            let iterations = u32::from_le_bytes(data[pos + 5..pos + 9].try_into().unwrap());
            let parallelism = data[pos + 9];
            pos += 10;
            kdf_chain.push(KdfDescriptor { id, memory_mb, iterations, parallelism });
        }

        if pos >= data.len() { return Err(Error::Format("truncated layer count".into())); }
        let layer_count = data[pos] as usize;
        pos += 1;

        let mut layers = Vec::with_capacity(layer_count);
        for _ in 0..layer_count {
            if pos + 2 > data.len() { return Err(Error::Format("truncated layer".into())); }
            let id = data[pos];
            let nonce_size = data[pos + 1];
            pos += 2;
            layers.push(LayerDescriptor { id, nonce_size });
        }

        let salt_end = pos.checked_add(32)
            .ok_or_else(|| Error::Format("salt offset overflow".into()))?;
        let commitment_end = salt_end.checked_add(32)
            .ok_or_else(|| Error::Format("commitment offset overflow".into()))?;
        if commitment_end > data.len() { return Err(Error::Format("truncated salt/commitment".into())); }
        let salt = data[pos..salt_end].to_vec();
        let commitment = data[salt_end..commitment_end].to_vec();
        pos = commitment_end;

        let header_len_end = pos.checked_add(4)
            .ok_or_else(|| Error::Format("header length offset overflow".into()))?;
        if header_len_end > data.len() { return Err(Error::Format("truncated header length".into())); }
        let header_len = u32::from_le_bytes(data[pos..header_len_end].try_into().unwrap()) as usize;
        pos = header_len_end;

        if pos != header_len {
            return Err(Error::Format(format!("header length mismatch: expected {header_len}, got {pos}")));
        }

        Ok((Self { version_major, version_minor, kdf_chain, layers, salt, commitment }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_header_round_trip() {
        let header = PublicHeader {
            version_major: 1,
            version_minor: 0,
            kdf_chain: vec![
                KdfDescriptor { id: 0x10, memory_mb: 1024, iterations: 1, parallelism: 1 },
                KdfDescriptor { id: 0x11, memory_mb: 1024, iterations: 4, parallelism: 4 },
            ],
            layers: vec![
                LayerDescriptor { id: 0x20, nonce_size: 16 },
                LayerDescriptor { id: 0x21, nonce_size: 16 },
                LayerDescriptor { id: 0x22, nonce_size: 24 },
            ],
            salt: vec![0xAA; 32],
            commitment: vec![0xBB; 32],
        };

        let bytes = header.serialize();
        assert_eq!(&bytes[..5], b"TOMB\n");

        let (parsed, consumed) = PublicHeader::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.version_major, 1);
        assert_eq!(parsed.version_minor, 0);
        assert_eq!(parsed.kdf_chain.len(), 2);
        assert_eq!(parsed.kdf_chain[0].id, 0x10);
        assert_eq!(parsed.kdf_chain[1].id, 0x11);
        assert_eq!(parsed.layers.len(), 3);
        assert_eq!(parsed.salt.len(), 32);
        assert_eq!(parsed.commitment.len(), 32);
    }

    #[test]
    fn public_header_magic_bytes() {
        let header = PublicHeader {
            version_major: 1,
            version_minor: 0,
            kdf_chain: vec![],
            layers: vec![],
            salt: vec![0; 32],
            commitment: vec![0; 32],
        };
        let bytes = header.serialize();
        assert_eq!(&bytes[..5], b"TOMB\n");
    }
}
