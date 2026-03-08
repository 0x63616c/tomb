use std::fs;
use std::time::Instant;

#[test]
#[ignore]
fn bench_seal_by_file_size() {
    let dir = std::env::temp_dir().join("tomb_bench");
    fs::create_dir_all(&dir).unwrap();

    let words: Vec<&str> = tomb::passphrase::wordlist::EFF_WORDLIST[..21].to_vec();
    let pass_str = words.join(" ");
    let passphrase = tomb::key::Passphrase::new(pass_str.into_bytes());

    let sizes: Vec<(u64, &str)> = vec![
        (1024, "1 KB"),
        (10 * 1024, "10 KB"),
        (100 * 1024, "100 KB"),
        (1024 * 1024, "1 MB"),
        (5 * 1024 * 1024, "5 MB"),
        (10 * 1024 * 1024, "10 MB"),
        (25 * 1024 * 1024, "25 MB"),
        (50 * 1024 * 1024, "50 MB"),
        (100 * 1024 * 1024, "100 MB"),
    ];

    println!();
    println!("{:<10} {:>10}", "Size", "Time");
    println!("{}", "-".repeat(22));

    for (size, label) in &sizes {
        let input = dir.join(format!("input_{}.bin", size));
        let output = dir.join(format!("output_{}.tomb", size));

        let data: Vec<u8> = (0..*size).map(|i| (i % 256) as u8).collect();
        fs::write(&input, &data).unwrap();

        let start = Instant::now();
        tomb::seal(
            &input,
            &output,
            &passphrase,
            None,
            &tomb::SealConfig::test(),
        )
        .unwrap();
        let elapsed = start.elapsed();

        println!("{:<10} {:>8.2?}", label, elapsed);

        fs::remove_file(&input).ok();
        fs::remove_file(&output).ok();
    }

    fs::remove_dir_all(&dir).ok();
}
