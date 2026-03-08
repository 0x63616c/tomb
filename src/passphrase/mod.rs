pub mod generate;
pub mod wordlist;

use crate::{Error, Result};

pub fn validate_passphrase(input: &str) -> Result<()> {
    let words: Vec<&str> = input.split_whitespace().collect();
    if words.len() != 21 {
        return Err(Error::PassphraseInvalid(format!(
            "expected 21 words, got {}",
            words.len()
        )));
    }
    for word in &words {
        if !wordlist::EFF_WORDLIST.contains(word) {
            return Err(Error::WordNotInList(word.to_string()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_21_valid_words() {
        let words: Vec<&str> = wordlist::EFF_WORDLIST[..21].to_vec();
        let input = words.join(" ");
        assert!(validate_passphrase(&input).is_ok());
    }

    #[test]
    fn validate_rejects_20_words() {
        let words: Vec<&str> = wordlist::EFF_WORDLIST[..20].to_vec();
        let input = words.join(" ");
        assert!(validate_passphrase(&input).is_err());
    }

    #[test]
    fn validate_rejects_22_words() {
        let words: Vec<&str> = wordlist::EFF_WORDLIST[..22].to_vec();
        let input = words.join(" ");
        assert!(validate_passphrase(&input).is_err());
    }

    #[test]
    fn validate_accepts_extra_whitespace() {
        let words: Vec<&str> = wordlist::EFF_WORDLIST[..21].to_vec();
        let input = format!("  {}  ", words.join("   "));
        assert!(validate_passphrase(&input).is_ok());
    }

    #[test]
    fn validate_rejects_non_eff_word() {
        let mut words: Vec<String> = wordlist::EFF_WORDLIST[..20]
            .iter()
            .map(|w| w.to_string())
            .collect();
        words.push("xyzzyplugh".into());
        let input = words.join(" ");
        let err = validate_passphrase(&input).unwrap_err();
        assert!(format!("{err}").contains("xyzzyplugh"));
    }
}
