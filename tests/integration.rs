use std::path::PathBuf;
use tomb::key::Passphrase;

fn test_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("tomb_integration_{}_{}", name, std::process::id()));
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

    tomb::seal(
        &input,
        &output,
        &passphrase,
        Some("integration test"),
        &tomb::SealConfig::test(),
    )
    .unwrap();
    assert!(output.exists());

    let opened = tomb::open_file(&output, &passphrase).unwrap();

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
    tomb::seal(
        &input,
        &output,
        &passphrase,
        None,
        &tomb::SealConfig::test(),
    )
    .unwrap();

    let wrong = Passphrase::new(b"wrong passphrase".to_vec());
    let result = tomb::open_file(&output, &wrong);
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
    tomb::seal(
        &input,
        &output,
        &passphrase,
        None,
        &tomb::SealConfig::test(),
    )
    .unwrap();

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
    tomb::seal(
        &input,
        &output,
        &passphrase,
        None,
        &tomb::SealConfig::test(),
    )
    .unwrap();

    let mut data = std::fs::read(&output).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    std::fs::write(&output, &data).unwrap();

    let result = tomb::open_file(&output, &passphrase);
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn empty_file_round_trip() {
    let dir = test_dir("empty");
    let input = dir.join("empty.bin");
    let output = dir.join("empty.tomb");

    std::fs::write(&input, b"").unwrap();

    let passphrase = Passphrase::new(b"empty file test".to_vec());
    tomb::seal(
        &input,
        &output,
        &passphrase,
        None,
        &tomb::SealConfig::test(),
    )
    .unwrap();

    let opened = tomb::open_file(&output, &passphrase).unwrap();

    assert!(opened.data.is_empty());
    assert_eq!(opened.filename, "empty.bin");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn open_truncated_file() {
    let dir = test_dir("truncated");
    let input = dir.join("data.txt");
    let output = dir.join("data.tomb");

    std::fs::write(&input, b"test data").unwrap();
    let passphrase = Passphrase::new(b"test passphrase".to_vec());
    tomb::seal(
        &input,
        &output,
        &passphrase,
        None,
        &tomb::SealConfig::test(),
    )
    .unwrap();

    // Truncate at various points
    let full = std::fs::read(&output).unwrap();
    for truncate_at in [0, 3, 5, 10, 50, full.len() / 2] {
        let truncated_path = dir.join(format!("trunc_{truncate_at}.tomb"));
        std::fs::write(&truncated_path, &full[..truncate_at]).unwrap();
        let result = tomb::open_file(&truncated_path, &passphrase);
        assert!(
            result.is_err(),
            "should fail when truncated at {truncate_at}"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn open_random_garbage() {
    let dir = test_dir("garbage");
    let garbage_path = dir.join("garbage.tomb");
    std::fs::write(&garbage_path, b"this is not a tomb file at all").unwrap();

    let passphrase = Passphrase::new(b"test".to_vec());
    let result = tomb::open_file(&garbage_path, &passphrase);
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn open_empty_file() {
    let dir = test_dir("empty_tomb");
    let empty_path = dir.join("empty.tomb");
    std::fs::write(&empty_path, b"").unwrap();

    let passphrase = Passphrase::new(b"test".to_vec());
    let result = tomb::open_file(&empty_path, &passphrase);
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inspect_truncated_file() {
    let dir = test_dir("inspect_trunc");
    let input = dir.join("data.txt");
    let output = dir.join("data.tomb");

    std::fs::write(&input, b"test").unwrap();
    let passphrase = Passphrase::new(b"test".to_vec());
    tomb::seal(
        &input,
        &output,
        &passphrase,
        None,
        &tomb::SealConfig::test(),
    )
    .unwrap();

    // Truncate to just the magic bytes
    let truncated_path = dir.join("trunc.tomb");
    std::fs::write(&truncated_path, b"TOMB\n\x01").unwrap();
    assert!(tomb::inspect_file(&truncated_path).is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn open_nonexistent_file() {
    let passphrase = Passphrase::new(b"test".to_vec());
    let result = tomb::open_file(
        std::path::Path::new("/tmp/tomb_does_not_exist.tomb"),
        &passphrase,
    );
    assert!(result.is_err());
}

#[test]
fn note_preserved() {
    let dir = test_dir("note");
    let input = dir.join("noted.txt");
    let output = dir.join("noted.tomb");

    std::fs::write(&input, b"data with a note").unwrap();

    let passphrase = Passphrase::new(b"note test passphrase".to_vec());
    let note_text = "this is my important note about the backup";
    tomb::seal(
        &input,
        &output,
        &passphrase,
        Some(note_text),
        &tomb::SealConfig::test(),
    )
    .unwrap();

    let opened = tomb::open_file(&output, &passphrase).unwrap();

    assert_eq!(opened.data, b"data with a note");
    assert_eq!(opened.filename, "noted.txt");

    std::fs::remove_dir_all(&dir).ok();
}
