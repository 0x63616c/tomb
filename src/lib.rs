pub mod key;
pub mod cipher;
pub mod pipeline;
pub mod format;
pub mod passphrase;
pub mod cli;

use std::fmt;

use rand::rngs::OsRng;
use rand::RngCore;

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
}
