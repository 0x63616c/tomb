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

#[test]
fn note_accessible_after_open() {
    let dir = test_dir("note_access");
    let input = dir.join("noted.txt");
    let output = dir.join("noted.tomb");

    std::fs::write(&input, b"some data").unwrap();
    let passphrase = Passphrase::new(b"note access test".to_vec());

    // Seal with a note
    tomb::seal(
        &input,
        &output,
        &passphrase,
        Some("hello world"),
        &tomb::SealConfig::test(),
    )
    .unwrap();

    let opened = tomb::open_file(&output, &passphrase).unwrap();
    assert_eq!(opened.note, Some("hello world".to_string()));

    // Seal without a note
    let output_no_note = dir.join("no_note.tomb");
    tomb::seal(
        &input,
        &output_no_note,
        &passphrase,
        None,
        &tomb::SealConfig::test(),
    )
    .unwrap();

    let opened_no_note = tomb::open_file(&output_no_note, &passphrase).unwrap();
    assert_eq!(opened_no_note.note, None);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn commitment_bypass_rejected() {
    let dir = test_dir("commitment");
    let input = dir.join("data.txt");
    let output = dir.join("data.tomb");

    std::fs::write(&input, b"commitment test data").unwrap();
    let passphrase = Passphrase::new(b"commitment test".to_vec());

    tomb::seal(
        &input,
        &output,
        &passphrase,
        None,
        &tomb::SealConfig::test(),
    )
    .unwrap();

    let mut data = std::fs::read(&output).unwrap();

    // Header format ends with: [salt:32][commitment:32][header_len:4 LE]
    // Parse header_len from the deserialized header
    let (_, header_len) = tomb::format::PublicHeader::deserialize(&data).unwrap();

    // Commitment is at header_len - 4 (header_len field) - 32 (commitment)
    let commitment_start = header_len - 4 - 32;
    let commitment_end = header_len - 4;

    // Zero out the commitment bytes
    for byte in &mut data[commitment_start..commitment_end] {
        *byte = 0x00;
    }
    std::fs::write(&output, &data).unwrap();

    let result = tomb::open_file(&output, &passphrase);
    match result {
        Err(e) => {
            let err = format!("{e}");
            assert!(
                err.contains("decryption failed"),
                "expected 'decryption failed', got: {err}"
            );
        }
        Ok(_) => panic!("expected open_file to fail after commitment patch"),
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn layer2_hmac_tamper_rejected() {
    let dir = test_dir("hmac_tamper");
    let input = dir.join("data.txt");
    let output = dir.join("data.tomb");

    // Use enough data to ensure substantial ciphertext body
    let content = vec![0xABu8; 1000];
    std::fs::write(&input, &content).unwrap();
    let passphrase = Passphrase::new(b"hmac tamper test".to_vec());

    tomb::seal(
        &input,
        &output,
        &passphrase,
        None,
        &tomb::SealConfig::test(),
    )
    .unwrap();

    let mut data = std::fs::read(&output).unwrap();

    // Find header length so we flip a byte in the ciphertext body, not the header
    let (_, header_len) = tomb::format::PublicHeader::deserialize(&data).unwrap();
    let body_len = data.len() - header_len;
    assert!(body_len > 10, "ciphertext body too short");

    // Flip a byte in the middle of the ciphertext body
    let flip_pos = header_len + body_len / 2;
    data[flip_pos] ^= 0xFF;
    std::fs::write(&output, &data).unwrap();

    let result = tomb::open_file(&output, &passphrase);
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn padme_length_edge_cases() {
    use tomb::format::padding::padme_length;

    // Small values all round up to 256
    assert_eq!(padme_length(0), 256);
    assert_eq!(padme_length(1), 256);
    assert_eq!(padme_length(256), 256);

    // Values above 256 round up but stay >= input
    assert!(padme_length(257) >= 257);
    assert!(padme_length(1024) >= 1024);

    // No panics for any of these (test completing proves this)
}

#[test]
fn unpad_bounds_check() {
    use tomb::format::padding::unpad;

    // original_size > data.len() should return Err, not panic
    let result = unpad(&[1, 2, 3], 100);
    assert!(result.is_err());

    // original_size == 0 should succeed
    let result = unpad(&[1, 2, 3], 0);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());

    // original_size == data.len() should succeed (exact match)
    let result = unpad(&[1, 2, 3], 3);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![1, 2, 3]);
}

#[test]
fn verify_sealed_direct() {
    use sha2::{Digest, Sha512};

    let dir = test_dir("verify_direct");
    let input = dir.join("data.txt");
    let output = dir.join("data.tomb");

    let content = b"verify sealed test data";
    std::fs::write(&input, content).unwrap();
    let passphrase = Passphrase::new(b"verify test".to_vec());
    let config = tomb::SealConfig::test();

    // Use composable API to seal without auto-verify
    let prepared = tomb::prepare_payload(&input, Some("verify note")).unwrap();
    let pipeline = tomb::pipeline::Pipeline::from_cipher_ids(&config.cipher_ids).unwrap();
    let keys = tomb::derive_keys(&passphrase, &pipeline, &config.kdf_chain).unwrap();

    let header = tomb::format::PublicHeader {
        version_major: tomb::format::FORMAT_VERSION_MAJOR,
        version_minor: tomb::format::FORMAT_VERSION_MINOR,
        kdf_chain: config.kdf_chain.clone(),
        layers: pipeline.layer_descriptors(),
        salt: keys.salt.clone(),
        commitment: keys.commitment.as_bytes().to_vec(),
    };

    tomb::encrypt_and_write(&output, &header, &pipeline, &keys.states, &prepared.padded).unwrap();

    // verify_sealed on untampered file should succeed
    let checksum: [u8; 64] = Sha512::digest(content).into();
    tomb::verify_sealed(&output, &passphrase, &checksum).unwrap();

    // Tamper with the file and verify again
    let mut data = std::fs::read(&output).unwrap();
    let (_, header_len) = tomb::format::PublicHeader::deserialize(&data).unwrap();
    let flip_pos = header_len + (data.len() - header_len) / 2;
    data[flip_pos] ^= 0xFF;
    std::fs::write(&output, &data).unwrap();

    let result = tomb::verify_sealed(&output, &passphrase, &checksum);
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn error_display_coverage() {
    use tomb::Error;

    // DecryptionFailed
    let e = Error::DecryptionFailed;
    assert!(format!("{e}").contains("decryption failed"));

    // Encryption
    let e = Error::Encryption("test error".into());
    let msg = format!("{e}");
    assert!(msg.contains("encryption error"));
    assert!(msg.contains("test error"));

    // KeyExpansion
    let e = Error::KeyExpansion;
    assert!(format!("{e}").contains("key expansion failed"));

    // Format
    let e = Error::Format("bad data".into());
    let msg = format!("{e}");
    assert!(msg.contains("format error"));
    assert!(msg.contains("bad data"));

    // VerificationFailed
    let e = Error::VerificationFailed;
    assert!(format!("{e}").contains("verification failed"));

    // PassphraseMismatch
    let e = Error::PassphraseMismatch;
    assert!(format!("{e}").contains("passphrases do not match"));

    // PassphraseInvalid
    let e = Error::PassphraseInvalid("too short".into());
    let msg = format!("{e}");
    assert!(msg.contains("invalid passphrase"));
    assert!(msg.contains("too short"));

    // WordNotInList
    let e = Error::WordNotInList("xyzzy".into());
    let msg = format!("{e}");
    assert!(msg.contains("xyzzy"));
    assert!(msg.contains("not in the EFF"));

    // UnknownLayer
    let e = Error::UnknownLayer(0xFF);
    let msg = format!("{e}");
    assert!(msg.contains("unknown layer"));
    assert!(msg.contains("0xff"));

    // UnknownKdf
    let e = Error::UnknownKdf(0xAB);
    let msg = format!("{e}");
    assert!(msg.contains("unknown KDF"));
    assert!(msg.contains("0xab"));

    // Io
    let e = Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
    let msg = format!("{e}");
    assert!(msg.contains("I/O error"));
    assert!(msg.contains("gone"));
}
