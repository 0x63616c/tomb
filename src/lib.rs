pub mod key;
pub mod cipher;
pub mod pipeline;
pub mod format;
pub mod passphrase;
pub mod cli;

use std::fmt;
use std::path::Path;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha512, Digest};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::format::inner::InnerHeader;
use crate::format::padding;
use crate::key::{MasterKey, Passphrase, Commitment};
use crate::key::derive::{Derive, ScryptDerive, Argon2idDerive, chain_derive};
use crate::key::expand::{LayerState, expand_layer_keys};
use crate::key::commit::compute_commitment;
use crate::pipeline::Pipeline;

// ── Error + Result ──────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    DecryptionFailed,
    Encryption(String),
    KeyExpansion,
    CommitmentMismatch,
    Format(String),
    VerificationFailed,
    PassphraseMismatch,
    PassphraseInvalid(String),
    WordNotInList(String),
    UnknownLayer(u8),
    UnknownKdf(u8),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::Encryption(msg) => write!(f, "encryption error: {msg}"),
            Self::KeyExpansion => write!(f, "key expansion failed"),
            Self::CommitmentMismatch => write!(f, "key commitment mismatch"),
            Self::Format(msg) => write!(f, "format error: {msg}"),
            Self::VerificationFailed => write!(f, "verification failed: sealed file does not match original"),
            Self::PassphraseMismatch => write!(f, "passphrases do not match"),
            Self::PassphraseInvalid(msg) => write!(f, "invalid passphrase: {msg}"),
            Self::WordNotInList(w) => write!(f, "'{w}' is not in the EFF diceware word list"),
            Self::UnknownLayer(id) => write!(f, "unknown layer type 0x{id:02x}, newer version of tomb may be required"),
            Self::UnknownKdf(id) => write!(f, "unknown KDF type 0x{id:02x}, newer version of tomb may be required"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ── Utilities ───────────────────────────────────────────────────────────

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

// ── Public Types ────────────────────────────────────────────────────────

pub struct PreparedPayload {
    pub padded: Vec<u8>,
    pub checksum: [u8; 64],
    pub inner: InnerHeader,
}

pub struct DerivedKeys {
    pub master: MasterKey,
    pub states: Vec<LayerState>,
    pub commitment: Commitment,
    pub salt: Vec<u8>,
}

pub struct OpenedFile {
    pub data: Vec<u8>,
    pub filename: String,
}

// ── Library API ─────────────────────────────────────────────────────────

pub fn prepare_payload(input_path: &Path, note: Option<&str>) -> Result<PreparedPayload> {
    let plaintext = fs::read(input_path)?;
    let checksum: [u8; 64] = Sha512::digest(&plaintext).into();

    let inner = InnerHeader {
        filename: input_path.file_name()
            .ok_or_else(|| Error::Format("no filename".into()))?
            .to_string_lossy()
            .into(),
        original_size: plaintext.len() as u64,
        checksum,
        sealed_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        tomb_version: env!("CARGO_PKG_VERSION").into(),
        note: note.map(String::from),
    };

    let mut payload = inner.serialize();
    payload.extend_from_slice(&plaintext);
    let padded = padding::pad(&payload);
    payload.zeroize();

    Ok(PreparedPayload { padded, checksum, inner })
}

/// Production key derivation (1GB scrypt + 1GB Argon2id)
pub fn derive_keys(passphrase: &Passphrase, pipeline: &Pipeline) -> Result<DerivedKeys> {
    derive_keys_internal(
        passphrase,
        pipeline,
        ScryptDerive::production(),
        Argon2idDerive::production(),
    )
}

/// Test key derivation (tiny params, fast)
pub fn derive_keys_with_params(passphrase: &Passphrase, pipeline: &Pipeline) -> Result<DerivedKeys> {
    derive_keys_internal(
        passphrase,
        pipeline,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    )
}

fn derive_keys_internal(
    passphrase: &Passphrase,
    pipeline: &Pipeline,
    scrypt: ScryptDerive,
    argon2: Argon2idDerive,
) -> Result<DerivedKeys> {
    let salt = random_bytes(32);

    let kdfs: Vec<Box<dyn Derive>> = vec![
        Box::new(scrypt),
        Box::new(argon2),
    ];
    let master = chain_derive(&kdfs, passphrase.as_bytes(), &salt)?;

    let layer_info = pipeline.layer_info();
    let states = expand_layer_keys(&master, &layer_info)?;
    let commitment = compute_commitment(&master);

    Ok(DerivedKeys { master, states, commitment, salt })
}

pub fn encrypt_and_write(
    output_path: &Path,
    header: &format::PublicHeader,
    pipeline: &Pipeline,
    states: &[LayerState],
    padded: &[u8],
) -> Result<()> {
    let sealed = pipeline.seal(states, padded)?;

    let header_bytes = header.serialize();
    let mut tomb_data = header_bytes;
    tomb_data.extend_from_slice(&sealed);

    // Atomic write: tmp file then rename
    let temp_path = output_path.with_extension("tomb.tmp");
    fs::write(&temp_path, &tomb_data)?;
    fs::rename(&temp_path, output_path)?;

    Ok(())
}

pub fn open_file(
    file_path: &Path,
    passphrase: &Passphrase,
) -> Result<OpenedFile> {
    open_file_with_params(file_path, passphrase, ScryptDerive::production(), Argon2idDerive::production())
}

pub fn open_file_with_params(
    file_path: &Path,
    passphrase: &Passphrase,
    scrypt: ScryptDerive,
    argon2: Argon2idDerive,
) -> Result<OpenedFile> {
    let tomb_data = fs::read(file_path)?;
    let (header, header_len) = format::PublicHeader::deserialize(&tomb_data)?;

    // Verify key commitment (constant-time via Commitment::verify)
    let kdfs: Vec<Box<dyn Derive>> = vec![Box::new(scrypt), Box::new(argon2)];
    let master = chain_derive(&kdfs, passphrase.as_bytes(), &header.salt)?;
    let commitment = compute_commitment(&master);
    let stored = Commitment::from_bytes(header.commitment.as_slice().try_into()
        .map_err(|_| Error::Format("invalid commitment length".into()))?);
    if !commitment.verify(&stored) {
        return Err(Error::DecryptionFailed);
    }

    let pipeline = Pipeline::build_from_header(&header)?;
    let layer_info = pipeline.layer_info();
    let states = expand_layer_keys(&master, &layer_info)?;

    let sealed_body = &tomb_data[header_len..];
    let decrypted = pipeline.open(&states, sealed_body)?;

    // Parse inner header
    let (inner, inner_len) = format::InnerHeader::deserialize(&decrypted)?;
    let plaintext = &decrypted[inner_len..inner_len + inner.original_size as usize];

    // Verify SHA-512 checksum (constant-time)
    let checksum: [u8; 64] = Sha512::digest(plaintext).into();
    if !bool::from(checksum[..].ct_eq(&inner.checksum[..])) {
        return Err(Error::DecryptionFailed);
    }

    Ok(OpenedFile {
        data: plaintext.to_vec(),
        filename: inner.filename,
    })
}

pub fn verify_sealed(
    output_path: &Path,
    passphrase: &Passphrase,
    expected_checksum: &[u8; 64],
    scrypt: ScryptDerive,
    argon2: Argon2idDerive,
) -> Result<()> {
    let opened = open_file_with_params(output_path, passphrase, scrypt, argon2)?;
    let checksum: [u8; 64] = Sha512::digest(&opened.data).into();
    if !bool::from(checksum[..].ct_eq(&expected_checksum[..])) {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

pub fn seal_with_params(
    input_path: &Path,
    output_path: &Path,
    passphrase: &Passphrase,
    note: Option<&str>,
) -> Result<()> {
    let prepared = prepare_payload(input_path, note)?;
    let pipeline = Pipeline::default_tomb();
    let keys = derive_keys_with_params(passphrase, &pipeline)?;

    let header = format::PublicHeader {
        version_major: 1,
        version_minor: 0,
        kdf_chain: vec![
            format::KdfDescriptor { id: 0x10, memory_mb: 1, iterations: 1, parallelism: 1 },
            format::KdfDescriptor { id: 0x11, memory_mb: 1, iterations: 1, parallelism: 1 },
        ],
        layers: pipeline.layer_descriptors(),
        salt: keys.salt.clone(),
        commitment: keys.commitment.as_bytes().to_vec(),
    };

    encrypt_and_write(output_path, &header, &pipeline, &keys.states, &prepared.padded)?;
    verify_sealed(output_path, passphrase, &prepared.checksum, ScryptDerive::test(), Argon2idDerive::test())?;

    Ok(())
}

pub fn seal(
    input_path: &Path,
    output_path: &Path,
    passphrase: &Passphrase,
    note: Option<&str>,
) -> Result<()> {
    let prepared = prepare_payload(input_path, note)?;
    let pipeline = Pipeline::default_tomb();
    let keys = derive_keys(passphrase, &pipeline)?;

    let header = format::PublicHeader {
        version_major: 1,
        version_minor: 0,
        kdf_chain: vec![
            format::KdfDescriptor { id: 0x10, memory_mb: 1024, iterations: 1, parallelism: 1 },
            format::KdfDescriptor { id: 0x11, memory_mb: 1024, iterations: 4, parallelism: 4 },
        ],
        layers: pipeline.layer_descriptors(),
        salt: keys.salt.clone(),
        commitment: keys.commitment.as_bytes().to_vec(),
    };

    encrypt_and_write(output_path, &header, &pipeline, &keys.states, &prepared.padded)?;
    verify_sealed(output_path, passphrase, &prepared.checksum, ScryptDerive::production(), Argon2idDerive::production())?;

    Ok(())
}

pub fn inspect_file(file_path: &Path) -> Result<format::PublicHeader> {
    let data = fs::read(file_path)?;
    let (header, _) = format::PublicHeader::deserialize(&data)?;
    Ok(header)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_decryption_failed() {
        let e = Error::DecryptionFailed;
        assert_eq!(format!("{e}"), "decryption failed");
    }

    #[test]
    fn error_display_unknown_layer() {
        let e = Error::UnknownLayer(0xFF);
        assert!(format!("{e}").contains("0xff"));
    }

    #[test]
    fn error_display_word_not_in_list() {
        let e = Error::WordNotInList("xyzzy".into());
        assert!(format!("{e}").contains("xyzzy"));
    }

    #[test]
    fn prepare_payload_includes_checksum() {
        let dir = std::env::temp_dir().join("tomb_test_prepare");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        let prepared = prepare_payload(&file_path, Some("test note")).unwrap();
        assert!(!prepared.padded.is_empty());
        assert_eq!(prepared.checksum.len(), 64);
        assert_eq!(prepared.inner.filename, "test.txt");
        assert_eq!(prepared.inner.original_size, 11);
        assert_eq!(prepared.inner.note.as_deref(), Some("test note"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn derive_keys_produces_states() {
        let passphrase = key::Passphrase::new(b"test passphrase words here".to_vec());
        let pipeline = pipeline::Pipeline::default_tomb();
        let keys = derive_keys_with_params(&passphrase, &pipeline).unwrap();
        assert_eq!(keys.states.len(), 3);
        assert_eq!(keys.salt.len(), 32);
        assert_eq!(keys.commitment.as_bytes().len(), 32);
    }

    #[test]
    fn seal_and_open_round_trip() {
        let dir = std::env::temp_dir().join("tomb_test_roundtrip");
        std::fs::create_dir_all(&dir).unwrap();

        let input = dir.join("secret.txt");
        let output = dir.join("secret.tomb");
        std::fs::write(&input, b"top secret data for tomb test").unwrap();

        let passphrase = key::Passphrase::new(b"test passphrase".to_vec());

        seal_with_params(&input, &output, &passphrase, Some("test note")).unwrap();
        assert!(output.exists());

        let opened = open_file_with_params(
            &output,
            &passphrase,
            key::derive::ScryptDerive::test(),
            key::derive::Argon2idDerive::test(),
        ).unwrap();
        assert_eq!(opened.data, b"top secret data for tomb test");
        assert_eq!(opened.filename, "secret.txt");

        std::fs::remove_dir_all(&dir).ok();
    }
}
