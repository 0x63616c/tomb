use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn tomb_bin() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_BIN_EXE_tomb"));
    // Fallback: if the path doesn't exist, try cargo build output
    if !path.exists() {
        path = PathBuf::from("target/debug/tomb");
    }
    path
}

fn test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tomb_cli_{}_{}", name, std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

// First 21 words from EFF diceware wordlist
const TEST_PASSPHRASE: &str =
    "abacus abdomen abdominal abide abiding ability ablaze able abnormal abrasion abrasive abreast abridge abroad abruptly absence absentee absently absinthe absolute absolve";

fn write_passphrase_file(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("passphrase.txt");
    fs::write(&path, format!("{TEST_PASSPHRASE}\n")).unwrap();
    path
}

fn tomb(args: &[&str], dir: &std::path::Path, pass_file: &std::path::Path) -> std::process::Output {
    Command::new(tomb_bin())
        .args(args)
        .arg("--passphrase-file")
        .arg(pass_file)
        .env("TOMB_TEST_PARAMS", "1")
        .current_dir(dir)
        .output()
        .expect("failed to run tomb")
}

fn tomb_no_pass(args: &[&str], dir: &std::path::Path) -> std::process::Output {
    Command::new(tomb_bin())
        .args(args)
        .env("TOMB_TEST_PARAMS", "1")
        .current_dir(dir)
        .output()
        .expect("failed to run tomb")
}

#[test]
fn seal_then_open_byte_identical() {
    let dir = test_dir("seal_open");
    let pass_file = write_passphrase_file(&dir);

    // Create test file with various content (binary + text + newlines)
    let content: Vec<u8> = {
        let mut v = b"Hello, world!\nSecond line\n\ttabbed\n".to_vec();
        v.extend_from_slice(&[0x00, 0xFF, 0x80, 0x7F]); // binary bytes
        v.extend_from_slice(b"\r\n\r\n"); // Windows-style line endings
        v.extend_from_slice(&[0u8; 100]); // null bytes
        v
    };
    let input = dir.join("test_file.bin");
    fs::write(&input, &content).unwrap();

    // Seal
    let output = tomb(
        &[
            "seal",
            input.to_str().unwrap(),
            "-o",
            dir.join("sealed.tomb").to_str().unwrap(),
            "--skip-verify",
        ],
        &dir,
        &pass_file,
    );
    assert!(
        output.status.success(),
        "seal failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.join("sealed.tomb").exists());

    // Open
    let output = tomb(
        &[
            "open",
            dir.join("sealed.tomb").to_str().unwrap(),
            "-o",
            dir.join("recovered.bin").to_str().unwrap(),
        ],
        &dir,
        &pass_file,
    );
    assert!(
        output.status.success(),
        "open failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Byte-for-byte identical
    let recovered = fs::read(dir.join("recovered.bin")).unwrap();
    assert_eq!(
        content, recovered,
        "recovered file is not byte-identical to original"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn seal_then_verify() {
    let dir = test_dir("verify");
    let pass_file = write_passphrase_file(&dir);

    let input = dir.join("data.txt");
    fs::write(&input, b"verify test data").unwrap();

    // Seal
    let output = tomb(
        &[
            "seal",
            input.to_str().unwrap(),
            "-o",
            dir.join("data.tomb").to_str().unwrap(),
            "--skip-verify",
        ],
        &dir,
        &pass_file,
    );
    assert!(output.status.success());

    // Verify
    let output = tomb(
        &["verify", dir.join("data.tomb").to_str().unwrap()],
        &dir,
        &pass_file,
    );
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Verified"),
        "expected 'Verified' in output: {stdout}"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn inspect_shows_header() {
    let dir = test_dir("inspect");
    let pass_file = write_passphrase_file(&dir);

    let input = dir.join("data.txt");
    fs::write(&input, b"inspect test").unwrap();

    // Seal
    let output = tomb(
        &[
            "seal",
            input.to_str().unwrap(),
            "-o",
            dir.join("data.tomb").to_str().unwrap(),
            "--skip-verify",
        ],
        &dir,
        &pass_file,
    );
    assert!(output.status.success());

    // Inspect (no passphrase needed)
    let output = tomb_no_pass(&["inspect", dir.join("data.tomb").to_str().unwrap()], &dir);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("format version: 1.0"),
        "missing version: {stdout}"
    );
    assert!(stdout.contains("scrypt"), "missing scrypt: {stdout}");
    assert!(stdout.contains("argon2id"), "missing argon2id: {stdout}");
    assert!(
        stdout.contains("cipher layers (3)"),
        "missing cipher layers: {stdout}"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn wrong_passphrase_fails() {
    let dir = test_dir("wrong_pass");
    let pass_file = write_passphrase_file(&dir);

    let input = dir.join("data.txt");
    fs::write(&input, b"secret").unwrap();

    // Seal with correct passphrase
    let output = tomb(
        &[
            "seal",
            input.to_str().unwrap(),
            "-o",
            dir.join("data.tomb").to_str().unwrap(),
            "--skip-verify",
        ],
        &dir,
        &pass_file,
    );
    assert!(output.status.success());

    // Try to open with different passphrase (last word changed)
    let wrong_pass = dir.join("wrong.txt");
    fs::write(&wrong_pass, "abacus abdomen abdominal abide abiding ability ablaze able abnormal abrasion abrasive abreast abridge abroad abruptly absence absentee absently absinthe absolute abstain\n").unwrap();
    let output = tomb(
        &["open", dir.join("data.tomb").to_str().unwrap()],
        &dir,
        &wrong_pass,
    );
    assert!(!output.status.success());

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn output_already_exists_fails() {
    let dir = test_dir("exists");
    let pass_file = write_passphrase_file(&dir);

    let input = dir.join("data.txt");
    fs::write(&input, b"test").unwrap();

    // Create output file first
    let tomb_file = dir.join("data.tomb");
    fs::write(&tomb_file, b"existing").unwrap();

    // Seal should fail because output exists
    let output = tomb(
        &[
            "seal",
            input.to_str().unwrap(),
            "-o",
            tomb_file.to_str().unwrap(),
        ],
        &dir,
        &pass_file,
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already exists"),
        "expected 'already exists': {stderr}"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn seal_with_note() {
    let dir = test_dir("note");
    let pass_file = write_passphrase_file(&dir);

    let input = dir.join("data.txt");
    fs::write(&input, b"noted content").unwrap();

    let output = tomb(
        &[
            "seal",
            input.to_str().unwrap(),
            "-o",
            dir.join("data.tomb").to_str().unwrap(),
            "--note",
            "my important note",
            "--skip-verify",
        ],
        &dir,
        &pass_file,
    );
    assert!(output.status.success());

    // Open and verify content is intact
    let output = tomb(
        &[
            "open",
            dir.join("data.tomb").to_str().unwrap(),
            "-o",
            dir.join("recovered.txt").to_str().unwrap(),
        ],
        &dir,
        &pass_file,
    );
    assert!(output.status.success());
    assert_eq!(
        fs::read(dir.join("recovered.txt")).unwrap(),
        b"noted content"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn filename_leak_warning() {
    let dir = test_dir("leak_warn");
    let pass_file = write_passphrase_file(&dir);

    let input = dir.join("secret");
    fs::write(&input, b"test").unwrap();

    // Output name "secret.tomb" contains input name "secret", so warning should fire
    let output = tomb(
        &[
            "seal",
            input.to_str().unwrap(),
            "-o",
            dir.join("secret.tomb").to_str().unwrap(),
            "--skip-verify",
        ],
        &dir,
        &pass_file,
    );
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("contains the original filename"),
        "expected leak warning: {stderr}"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn seal_default_output_name() {
    let dir = test_dir("default_name");
    let pass_file = write_passphrase_file(&dir);

    let input = dir.join("myfile.txt");
    fs::write(&input, b"test").unwrap();

    let output = tomb(
        &["seal", input.to_str().unwrap(), "--skip-verify"],
        &dir,
        &pass_file,
    );
    assert!(output.status.success());
    // Default output should be myfile.tomb
    assert!(dir.join("myfile.tomb").exists());

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn empty_file_round_trip() {
    let dir = test_dir("empty_cli");
    let pass_file = write_passphrase_file(&dir);

    let input = dir.join("empty.bin");
    fs::write(&input, b"").unwrap();

    let output = tomb(
        &[
            "seal",
            input.to_str().unwrap(),
            "-o",
            dir.join("empty.tomb").to_str().unwrap(),
            "--skip-verify",
        ],
        &dir,
        &pass_file,
    );
    assert!(output.status.success());

    let output = tomb(
        &[
            "open",
            dir.join("empty.tomb").to_str().unwrap(),
            "-o",
            dir.join("recovered.bin").to_str().unwrap(),
        ],
        &dir,
        &pass_file,
    );
    assert!(output.status.success());
    assert_eq!(fs::read(dir.join("recovered.bin")).unwrap(), b"");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn open_preserves_original_filename() {
    let dir = test_dir("orig_name");
    let pass_file = write_passphrase_file(&dir);

    let input = dir.join("original_name.dat");
    fs::write(&input, b"data").unwrap();

    let output = tomb(
        &[
            "seal",
            input.to_str().unwrap(),
            "-o",
            dir.join("sealed.tomb").to_str().unwrap(),
            "--skip-verify",
        ],
        &dir,
        &pass_file,
    );
    assert!(output.status.success());

    // Delete original so open can write to that filename
    fs::remove_file(&input).unwrap();

    // Open without -o should use original filename
    let output = tomb(
        &["open", dir.join("sealed.tomb").to_str().unwrap()],
        &dir,
        &pass_file,
    );
    assert!(
        output.status.success(),
        "open failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.join("original_name.dat").exists());
    assert_eq!(fs::read(dir.join("original_name.dat")).unwrap(), b"data");

    fs::remove_dir_all(&dir).ok();
}
