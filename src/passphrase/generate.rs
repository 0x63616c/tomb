use crate::passphrase::wordlist::EFF_WORDLIST;

use rand::rngs::OsRng;
use rand::Rng;

pub fn generate_passphrase(word_count: usize) -> Vec<String> {
    let mut words = Vec::with_capacity(word_count);
    for _ in 0..word_count {
        let index = OsRng.gen_range(0..EFF_WORDLIST.len());
        words.push(EFF_WORDLIST[index].to_string());
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passphrase::wordlist::EFF_WORDLIST;

    #[test]
    fn generate_produces_21_words() {
        let words = generate_passphrase(21);
        assert_eq!(words.len(), 21);
    }

    #[test]
    fn generate_all_words_in_list() {
        let words = generate_passphrase(21);
        for word in &words {
            assert!(
                EFF_WORDLIST.contains(&word.as_str()),
                "'{word}' not in EFF list"
            );
        }
    }

    #[test]
    fn generate_produces_different_output() {
        let a = generate_passphrase(21);
        let b = generate_passphrase(21);
        assert_ne!(a, b);
    }
}
