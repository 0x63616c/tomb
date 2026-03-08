use std::time::Instant;

use tomb::cipher::aes::AesCtr;
use tomb::cipher::twofish::TwofishCtr;
use tomb::cipher::xchacha::XChaCha;
use tomb::cipher::CipherLayer;
use tomb::pipeline::envelope::LayerEnvelope;

#[test]
fn bench_individual_ciphers_10mb() {
    let size = 10 * 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i: usize| (i % 256) as u8).collect();

    // Derive real keys through the proper API
    let words: Vec<&str> = tomb::passphrase::wordlist::EFF_WORDLIST[..21].to_vec();
    let passphrase = tomb::key::Passphrase::new(words.join(" ").into_bytes());
    let config = tomb::SealConfig::test();
    let pipeline = tomb::pipeline::Pipeline::from_cipher_ids(&config.cipher_ids).unwrap();
    let keys = tomb::derive_keys(&passphrase, &pipeline, &config.kdf_chain).unwrap();

    println!("\n=== Individual operations on 10 MB ===\n");

    // Twofish
    let cipher = TwofishCtr;
    let state = &keys.states[0];
    let start = Instant::now();
    let enc = cipher
        .encrypt(&state.encrypt_key, &state.nonce, &data)
        .unwrap();
    let t = start.elapsed();
    println!(
        "twofish encrypt:   {:>8.2?}  ({:.1} MB/s)",
        t,
        size as f64 / t.as_secs_f64() / 1024.0 / 1024.0
    );
    let start = Instant::now();
    LayerEnvelope::compute_mac(&state.mac_key, cipher.id(), &state.nonce, &enc);
    let t = start.elapsed();
    println!(
        "twofish HMAC:      {:>8.2?}  ({:.1} MB/s)",
        t,
        size as f64 / t.as_secs_f64() / 1024.0 / 1024.0
    );

    // AES
    let cipher = AesCtr;
    let state = &keys.states[1];
    let start = Instant::now();
    let enc = cipher
        .encrypt(&state.encrypt_key, &state.nonce, &data)
        .unwrap();
    let t = start.elapsed();
    println!(
        "aes encrypt:       {:>8.2?}  ({:.1} MB/s)",
        t,
        size as f64 / t.as_secs_f64() / 1024.0 / 1024.0
    );
    let start = Instant::now();
    LayerEnvelope::compute_mac(&state.mac_key, cipher.id(), &state.nonce, &enc);
    let t = start.elapsed();
    println!(
        "aes HMAC:          {:>8.2?}  ({:.1} MB/s)",
        t,
        size as f64 / t.as_secs_f64() / 1024.0 / 1024.0
    );

    // XChaCha20
    let cipher = XChaCha;
    let state = &keys.states[2];
    let start = Instant::now();
    let enc = cipher
        .encrypt(&state.encrypt_key, &state.nonce, &data)
        .unwrap();
    let t = start.elapsed();
    println!(
        "xchacha20 encrypt: {:>8.2?}  ({:.1} MB/s)",
        t,
        size as f64 / t.as_secs_f64() / 1024.0 / 1024.0
    );
    let start = Instant::now();
    LayerEnvelope::compute_mac(&state.mac_key, cipher.id(), &state.nonce, &enc);
    let t = start.elapsed();
    println!(
        "xchacha20 HMAC:    {:>8.2?}  ({:.1} MB/s)",
        t,
        size as f64 / t.as_secs_f64() / 1024.0 / 1024.0
    );

    // Allocation/copy overhead
    println!();
    let start = Instant::now();
    let _copy = data.to_vec();
    println!("vec copy (10MB):   {:>8.2?}", start.elapsed());

    let start = Instant::now();
    let mut z = data.to_vec();
    zeroize::Zeroize::zeroize(&mut z[..]);
    println!("vec zeroize (10MB):{:>8.2?}", start.elapsed());
}
