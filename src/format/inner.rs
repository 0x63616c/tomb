use crate::{Error, Result};

pub struct InnerHeader {
    pub filename: String,
    pub original_size: u64,
    pub checksum: [u8; 64],
    pub sealed_at: u64,
    pub tomb_version: String,
    pub note: Option<String>,
}

impl InnerHeader {
    /// Serialize: [filename_len:2 LE][filename][original_size:8 LE][checksum:64]
    ///            [sealed_at:8 LE][version_len:2 LE][version]
    ///            [has_note:1][note_len:2 LE][note]  (note fields only if has_note=1)
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        let fname = self.filename.as_bytes();
        out.extend_from_slice(&(fname.len() as u16).to_le_bytes());
        out.extend_from_slice(fname);

        out.extend_from_slice(&self.original_size.to_le_bytes());
        out.extend_from_slice(&self.checksum);
        out.extend_from_slice(&self.sealed_at.to_le_bytes());

        let ver = self.tomb_version.as_bytes();
        out.extend_from_slice(&(ver.len() as u16).to_le_bytes());
        out.extend_from_slice(ver);

        match &self.note {
            Some(note) => {
                out.push(1);
                let note_bytes = note.as_bytes();
                out.extend_from_slice(&(note_bytes.len() as u16).to_le_bytes());
                out.extend_from_slice(note_bytes);
            }
            None => {
                out.push(0);
            }
        }

        out
    }

    pub fn deserialize(data: &[u8]) -> Result<(Self, usize)> {
        let mut pos = 0;

        let read_u16 = |data: &[u8], pos: &mut usize| -> Result<u16> {
            if *pos + 2 > data.len() { return Err(Error::Format("truncated".into())); }
            let val = u16::from_le_bytes(data[*pos..*pos + 2].try_into().unwrap());
            *pos += 2;
            Ok(val)
        };

        let read_u64 = |data: &[u8], pos: &mut usize| -> Result<u64> {
            if *pos + 8 > data.len() { return Err(Error::Format("truncated".into())); }
            let val = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            Ok(val)
        };

        let fname_len = read_u16(data, &mut pos)? as usize;
        let fname_end = pos.checked_add(fname_len)
            .ok_or_else(|| Error::Format("filename length overflow".into()))?;
        if fname_end > data.len() { return Err(Error::Format("truncated filename".into())); }
        let filename = String::from_utf8(data[pos..fname_end].to_vec())
            .map_err(|_| Error::Format("invalid utf8 filename".into()))?;
        pos = fname_end;

        let original_size = read_u64(data, &mut pos)?;

        if pos + 64 > data.len() { return Err(Error::Format("truncated checksum".into())); }
        let mut checksum = [0u8; 64];
        checksum.copy_from_slice(&data[pos..pos + 64]);
        pos += 64;

        let sealed_at = read_u64(data, &mut pos)?;

        let ver_len = read_u16(data, &mut pos)? as usize;
        let ver_end = pos.checked_add(ver_len)
            .ok_or_else(|| Error::Format("version length overflow".into()))?;
        if ver_end > data.len() { return Err(Error::Format("truncated version".into())); }
        let tomb_version = String::from_utf8(data[pos..ver_end].to_vec())
            .map_err(|_| Error::Format("invalid utf8 version".into()))?;
        pos = ver_end;

        if pos >= data.len() { return Err(Error::Format("truncated note flag".into())); }
        let has_note = data[pos];
        pos += 1;

        let note = if has_note == 1 {
            let note_len = read_u16(data, &mut pos)? as usize;
            let note_end = pos.checked_add(note_len)
                .ok_or_else(|| Error::Format("note length overflow".into()))?;
            if note_end > data.len() { return Err(Error::Format("truncated note".into())); }
            let n = String::from_utf8(data[pos..note_end].to_vec())
                .map_err(|_| Error::Format("invalid utf8 note".into()))?;
            pos = note_end;
            Some(n)
        } else {
            None
        };

        Ok((Self { filename, original_size, checksum, sealed_at, tomb_version, note }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inner_header_round_trip() {
        let header = InnerHeader {
            filename: "secret.json".into(),
            original_size: 12345,
            checksum: [0xAA; 64],
            sealed_at: 1700000000,
            tomb_version: "0.1.0".into(),
            note: Some("test note".into()),
        };
        let bytes = header.serialize();
        let (parsed, consumed) = InnerHeader::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.filename, "secret.json");
        assert_eq!(parsed.original_size, 12345);
        assert_eq!(parsed.checksum, [0xAA; 64]);
        assert_eq!(parsed.sealed_at, 1700000000);
        assert_eq!(parsed.tomb_version, "0.1.0");
        assert_eq!(parsed.note.as_deref(), Some("test note"));
    }

    #[test]
    fn inner_header_no_note() {
        let header = InnerHeader {
            filename: "file.txt".into(),
            original_size: 100,
            checksum: [0u8; 64],
            sealed_at: 0,
            tomb_version: "0.1.0".into(),
            note: None,
        };
        let bytes = header.serialize();
        let (parsed, _) = InnerHeader::deserialize(&bytes).unwrap();
        assert!(parsed.note.is_none());
    }
}
