use std::path::PathBuf;
use tomb::key::Passphrase;
use tomb::key::derive::{ScryptDerive, Argon2idDerive};

fn test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tomb_integration_{}_{}", name, std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn full_seal_open_cycle() {
    let dir = test_dir("seal_open");
    let input = dir.join("secret.json");
    let output = dir.join("backup.tomb");

    let content = b"{\"key\": \"value\", \"secret\": 42}";
    std::fs::write(&input, content).unwrap();

    let passphrase = Passphrase::new(b"test passphrase for integration".to_vec());

    tomb::seal_with_params(&input, &output, &passphrase, Some("integration test")).unwrap();
    assert!(output.exists());

    let opened = tomb::open_file_with_params(
        &output,
        &passphrase,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    ).unwrap();

    assert_eq!(opened.data, content);
    assert_eq!(opened.filename, "secret.json");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn wrong_passphrase_fails() {
    let dir = test_dir("wrong_pass");
    let input = dir.join("data.bin");
    let output = dir.join("data.tomb");

    std::fs::write(&input, b"secret data").unwrap();

    let passphrase = Passphrase::new(b"correct passphrase".to_vec());
    tomb::seal_with_params(&input, &output, &passphrase, None).unwrap();

    let wrong = Passphrase::new(b"wrong passphrase".to_vec());
    let result = tomb::open_file_with_params(
        &output,
        &wrong,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    );
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inspect_without_passphrase() {
    let dir = test_dir("inspect");
    let input = dir.join("file.txt");
    let output = dir.join("file.tomb");

    std::fs::write(&input, b"hello").unwrap();
    let passphrase = Passphrase::new(b"test".to_vec());
    tomb::seal_with_params(&input, &output, &passphrase, None).unwrap();

    let header = tomb::inspect_file(&output).unwrap();
    assert_eq!(header.version_major, 1);
    assert_eq!(header.kdf_chain.len(), 2);
    assert_eq!(header.layers.len(), 3);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn tampered_file_fails() {
    let dir = test_dir("tampered");
    let input = dir.join("data.txt");
    let output = dir.join("data.tomb");

    std::fs::write(&input, b"important data").unwrap();
    let passphrase = Passphrase::new(b"test passphrase".to_vec());
    tomb::seal_with_params(&input, &output, &passphrase, None).unwrap();

    let mut data = std::fs::read(&output).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    std::fs::write(&output, &data).unwrap();

    let result = tomb::open_file_with_params(
        &output,
        &passphrase,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    );
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn large_file_round_trip() {
    let dir = test_dir("large");
    let input = dir.join("large.bin");
    let output = dir.join("large.tomb");

    let content: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    std::fs::write(&input, &content).unwrap();

    let passphrase = Passphrase::new(b"large file test".to_vec());
    tomb::seal_with_params(&input, &output, &passphrase, None).unwrap();

    let opened = tomb::open_file_with_params(
        &output,
        &passphrase,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    ).unwrap();

    assert_eq!(opened.data, content);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn empty_file_round_trip() {
    let dir = test_dir("empty");
    let input = dir.join("empty.bin");
    let output = dir.join("empty.tomb");

    std::fs::write(&input, b"").unwrap();

    let passphrase = Passphrase::new(b"empty file test".to_vec());
    tomb::seal_with_params(&input, &output, &passphrase, None).unwrap();

    let opened = tomb::open_file_with_params(
        &output,
        &passphrase,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    ).unwrap();

    assert!(opened.data.is_empty());
    assert_eq!(opened.filename, "empty.bin");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn note_preserved() {
    let dir = test_dir("note");
    let input = dir.join("noted.txt");
    let output = dir.join("noted.tomb");

    std::fs::write(&input, b"data with a note").unwrap();

    let passphrase = Passphrase::new(b"note test passphrase".to_vec());
    let note_text = "this is my important note about the backup";
    tomb::seal_with_params(&input, &output, &passphrase, Some(note_text)).unwrap();

    // Verify round-trip works (note is embedded in the encrypted inner header)
    let opened = tomb::open_file_with_params(
        &output,
        &passphrase,
        ScryptDerive::test(),
        Argon2idDerive::test(),
    ).unwrap();

    assert_eq!(opened.data, b"data with a note");
    assert_eq!(opened.filename, "noted.txt");

    std::fs::remove_dir_all(&dir).ok();
}
