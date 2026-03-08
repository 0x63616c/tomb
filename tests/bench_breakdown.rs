use std::time::Instant;

/// Benchmark to isolate where time is spent per-component.
/// Tests with 10MB to keep it fast but meaningful.
#[test]
#[ignore]
fn bench_breakdown_10mb() {
    let dir = std::env::temp_dir().join("tomb_bench_breakdown");
    std::fs::create_dir_all(&dir).unwrap();

    let words: Vec<&str> = tomb::passphrase::wordlist::EFF_WORDLIST[..21].to_vec();
    let pass_str = words.join(" ");
    let passphrase = tomb::key::Passphrase::new(pass_str.into_bytes());

    let size = 10 * 1024 * 1024; // 10 MB
    let input = dir.join("input.bin");
    let output = dir.join("output.tomb");
    let data: Vec<u8> = (0..size).map(|i: u64| (i % 256) as u8).collect();
    std::fs::write(&input, &data).unwrap();

    println!("\n=== 10 MB breakdown ===\n");

    // 1. prepare_payload
    let start = Instant::now();
    let prepared = tomb::prepare_payload(&input, None).unwrap();
    println!(
        "prepare_payload:    {:>8.2?}  (read + SHA-512 + PADME pad)",
        start.elapsed()
    );
    println!(
        "  padded size:      {} bytes ({:.1} MB)",
        prepared.padded.len(),
        prepared.padded.len() as f64 / 1024.0 / 1024.0
    );

    // 2. derive_keys (test params, basically free)
    let config = tomb::SealConfig::test();
    let pipeline = tomb::pipeline::Pipeline::from_cipher_ids(&config.cipher_ids).unwrap();
    let start = Instant::now();
    let keys = tomb::derive_keys(&passphrase, &pipeline, &config.kdf_chain).unwrap();
    println!(
        "derive_keys (test): {:>8.2?}  (scrypt + argon2id, test params)",
        start.elapsed()
    );

    // 3. pipeline.seal (encrypt through 3 layers)
    let start = Instant::now();
    let sealed = pipeline.seal(&keys.states, &prepared.padded).unwrap();
    println!(
        "pipeline.seal:      {:>8.2?}  (3x encrypt + 3x HMAC)",
        start.elapsed()
    );
    println!(
        "  sealed size:      {} bytes ({:.1} MB)",
        sealed.len(),
        sealed.len() as f64 / 1024.0 / 1024.0
    );

    // 4. serialize + write
    let header = tomb::format::PublicHeader {
        version_major: tomb::format::FORMAT_VERSION_MAJOR,
        version_minor: tomb::format::FORMAT_VERSION_MINOR,
        kdf_chain: config.kdf_chain.clone(),
        layers: pipeline.layer_descriptors(),
        salt: keys.salt.clone(),
        commitment: keys.commitment.as_bytes().to_vec(),
    };
    let start = Instant::now();
    let header_bytes = header.serialize();
    let mut tomb_data = header_bytes;
    tomb_data.extend_from_slice(&sealed);
    std::fs::write(&output, &tomb_data).unwrap();
    println!(
        "serialize + write:  {:>8.2?}  (header + sealed -> disk)",
        start.elapsed()
    );

    // 5. verify (read + KDF + decrypt)
    let start = Instant::now();
    let opened = tomb::open_file(&output, &passphrase).unwrap();
    println!(
        "verify (open):      {:>8.2?}  (read + KDF + 3x HMAC-verify + 3x decrypt)",
        start.elapsed()
    );

    drop(opened);
    drop(sealed);

    // Benchmark seal vs open separately for symmetry check
    println!("\n=== seal-only vs open-only (10 MB) ===\n");

    let start = Instant::now();
    let sealed2 = pipeline.seal(&keys.states, &prepared.padded).unwrap();
    let seal_time = start.elapsed();
    println!("pipeline.seal:      {:>8.2?}", seal_time);

    let start = Instant::now();
    let _opened2 = pipeline.open(&keys.states, &sealed2).unwrap();
    let open_time = start.elapsed();
    println!("pipeline.open:      {:>8.2?}", open_time);

    println!("\ntotal seal+open:    {:>8.2?}", seal_time + open_time);
    println!(
        "ratio open/seal:    {:.2}x",
        open_time.as_secs_f64() / seal_time.as_secs_f64()
    );

    // Memory allocation profile: how many Vec allocations for 10MB?
    // Each layer: data.to_vec() + encrypted vec + envelope serialize vec
    // = 3 allocs per layer * 3 layers = 9 allocs of ~10MB each during seal
    // Plus the zeroize passes

    std::fs::remove_dir_all(&dir).ok();
}
