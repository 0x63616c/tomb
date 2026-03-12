use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::key::Passphrase;
use crate::passphrase::{generate::generate_passphrase, validate_passphrase};
use crate::{Error, Result, SealConfig};

#[derive(Parser)]
#[command(
    name = "tomb",
    version,
    long_version = concat!(
        env!("CARGO_PKG_VERSION"),
        " (",
        env!("TOMB_GIT_SHA"),
        ")"
    ),
    about = "Encrypt anything with a passphrase. Recover it decades later.",
    arg_required_else_help = true,
    after_help = "Examples:
  tomb generate                          Generate a 21-word passphrase
  tomb seal secrets.json                 Encrypt with default output (secrets.tomb)
  tomb seal secrets.json -o backup.tomb  Encrypt with custom output name
  tomb seal data.tar --note \"march 2026\" Encrypt with a note
  tomb open backup.tomb                  Decrypt to original filename
  tomb open backup.tomb -o restored.json Decrypt to custom path
  tomb verify backup.tomb                Confirm file is decryptable
  tomb inspect backup.tomb               View header without passphrase"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Encrypt a file with three layers of authenticated encryption
    Seal {
        /// Path to the file to encrypt
        file: PathBuf,
        /// Output path [default: <FILE>.tomb]
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Attach a note (stored encrypted inside the file)
        #[arg(long, value_name = "TEXT")]
        note: Option<String>,
        /// Skip post-seal verification
        #[arg(long)]
        skip_verify: bool,
        /// Read passphrase from a file instead of prompting
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,
    },
    /// Decrypt a .tomb file back to the original
    Open {
        /// Path to the .tomb file
        file: PathBuf,
        /// Output path [default: original filename from header]
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Read passphrase from a file instead of prompting
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,
    },
    /// Verify a .tomb file is decryptable without extracting
    Verify {
        /// Path to the .tomb file
        file: PathBuf,
        /// Read passphrase from a file instead of prompting
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,
    },
    /// Show public header details (no passphrase needed)
    Inspect {
        /// Path to the .tomb file
        file: PathBuf,
    },
    /// Generate a random 21-word diceware passphrase
    Generate,
    /// Update tomb to the latest release
    Update,
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    let pass = rpassword::prompt_password(prompt).map_err(|e| Error::Io(io::Error::other(e)))?;
    Ok(pass)
}

/// Prompt for a passphrase that may be entered across multiple lines.
///
/// Keeps reading masked lines (via `rpassword`) and accumulating words until
/// exactly `expected_words` have been entered. If a line pushes the total past
/// the target, returns an error immediately — never silently truncates.
///
/// This handles all paste/typing styles:
/// - All words on one line (single paste)
/// - 7 words per line (copy-paste of the chunked display)
/// - One word at a time
fn prompt_passphrase_multiline(expected_words: usize) -> Result<String> {
    let mut collected: Vec<String> = Vec::new();

    loop {
        let remaining = expected_words - collected.len();
        let prompt = if collected.is_empty() {
            format!("Passphrase ({expected_words} words): ")
        } else {
            format!("  ({remaining} words remaining): ")
        };

        let line =
            rpassword::prompt_password(&prompt).map_err(|e| Error::Io(io::Error::other(e)))?;
        let words: Vec<&str> = line.split_whitespace().collect();

        if words.is_empty() {
            continue;
        }

        collected.extend(words.iter().map(|w| w.to_string()));

        if collected.len() == expected_words {
            return Ok(collected.join(" "));
        }

        if collected.len() > expected_words {
            return Err(Error::PassphraseInvalid(format!(
                "too many words (expected {expected_words}, got {})",
                collected.len()
            )));
        }
    }
}

/// Normalize whitespace: trim leading/trailing, collapse multiple spaces to single space.
fn normalize_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn read_passphrase_file(path: &Path) -> Result<Passphrase> {
    let mut contents = fs::read_to_string(path)?;
    let pass = normalize_whitespace(contents.trim_end_matches('\n'));
    contents.zeroize();
    Ok(Passphrase::new(pass.into_bytes()))
}

fn passphrase_for_seal(passphrase_file: Option<&Path>) -> Result<Passphrase> {
    if let Some(path) = passphrase_file {
        let passphrase = read_passphrase_file(path)?;
        validate_passphrase(&String::from_utf8_lossy(passphrase.as_bytes()))?;
        return Ok(passphrase);
    }

    let mut p1_raw = prompt_passphrase("Enter passphrase (or press Enter to generate one): ")?;
    let mut p1 = normalize_whitespace(&p1_raw);
    p1_raw.zeroize();

    if p1.is_empty() {
        let words = generate_passphrase(21);

        // Alternate screen buffer
        print!("\x1b[?1049h");
        println!("\nYour passphrase (21 words):\n");
        for chunk in words.chunks(7) {
            println!("  {}", chunk.join(" "));
        }
        println!("\nWrite this down somewhere safe. Press Enter when done...");
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).ok();
        print!("\x1b[?1049l");

        println!("Re-enter your passphrase to confirm:");
        let mut entered = prompt_passphrase_multiline(21)?;
        let mut generated = words.join(" ");
        if !bool::from(entered.as_bytes().ct_eq(generated.as_bytes())) {
            entered.zeroize();
            generated.zeroize();
            return Err(Error::PassphraseMismatch);
        }
        entered.zeroize();
        Ok(Passphrase::new(generated.into_bytes()))
    } else {
        validate_passphrase(&p1)?;
        let mut p2_raw = prompt_passphrase("Confirm passphrase: ")?;
        let mut p2 = normalize_whitespace(&p2_raw);
        p2_raw.zeroize();
        if !bool::from(p1.as_bytes().ct_eq(p2.as_bytes())) {
            p2.zeroize();
            p1.zeroize();
            return Err(Error::PassphraseMismatch);
        }
        p2.zeroize();
        Ok(Passphrase::new(p1.into_bytes()))
    }
}

fn passphrase_for_open(passphrase_file: Option<&Path>) -> Result<Passphrase> {
    if let Some(path) = passphrase_file {
        return read_passphrase_file(path);
    }
    let mut pass_raw = prompt_passphrase("Enter passphrase: ")?;
    let pass = normalize_whitespace(&pass_raw);
    pass_raw.zeroize();
    Ok(Passphrase::new(pass.into_bytes()))
}

fn cli_config() -> SealConfig {
    #[cfg(debug_assertions)]
    if std::env::var("TOMB_TEST_PARAMS").is_ok() {
        return SealConfig::test();
    }
    SealConfig::production()
}

fn run_update() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let target = env!("TOMB_TARGET");

    // Fetch latest release tag from GitHub API
    let api_url = "https://api.github.com/repos/0x63616c/tomb/releases/latest";
    let response = std::process::Command::new("curl")
        .args(["-fsSL", "--user-agent", "tomb-updater", api_url])
        .output()
        .map_err(Error::Io)?;

    if !response.status.success() {
        return Err(Error::Format("Failed to fetch latest release info".into()));
    }

    let body = String::from_utf8_lossy(&response.stdout);
    let tag = extract_json_string(&body, "tag_name")
        .ok_or_else(|| Error::Format("Could not parse release tag from GitHub API".into()))?;

    let latest = tag.trim_start_matches('v');

    if latest == current {
        println!("Already up to date ({})", current);
        return Ok(());
    }

    println!("Updating {} -> {}...", current, latest);

    // Download tarball to temp dir
    let tarball_name = format!("tomb-{}-{}.tar.gz", tag, target);
    let url = format!(
        "https://github.com/0x63616c/tomb/releases/download/{}/{}",
        tag, tarball_name
    );

    let tmp = std::env::temp_dir().join(format!("tomb-update-{}", latest));
    std::fs::create_dir_all(&tmp)?;

    let tarball_path = tmp.join(&tarball_name);

    let download = std::process::Command::new("curl")
        .args(["-fsSL", "-o", tarball_path.to_str().unwrap(), &url])
        .status()
        .map_err(Error::Io)?;

    if !download.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(Error::Format(format!(
            "Failed to download {}. Is {} a supported platform?",
            url, target
        )));
    }

    // Extract binary
    let extract = std::process::Command::new("tar")
        .args([
            "xzf",
            tarball_path.to_str().unwrap(),
            "-C",
            tmp.to_str().unwrap(),
        ])
        .status()
        .map_err(Error::Io)?;

    if !extract.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(Error::Format("Failed to extract tarball".into()));
    }

    // Atomically replace own binary
    let new_binary = tmp.join("tomb");
    let current_exe = std::env::current_exe().map_err(Error::Io)?;

    // Write to a sibling temp file then rename (atomic on POSIX)
    let tmp_exe = current_exe.with_extension("tmp");
    std::fs::copy(&new_binary, &tmp_exe)?;
    std::fs::rename(&tmp_exe, &current_exe)?;

    let _ = std::fs::remove_dir_all(&tmp);

    println!("Updated to {}. Run 'tomb --version' to confirm.", latest);
    Ok(())
}

/// Extract a string value from JSON by key. Simple, no dep.
/// Works for flat string fields like `"tag_name": "v0.1.0"`.
fn extract_json_string<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let search = format!("\"{}\"", key);
    let key_pos = json.find(&search)?;
    let after_key = &json[key_pos + search.len()..];
    // Skip whitespace and colon
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let value_start = &after_colon[1..];
    let value_end = value_start.find('"')?;
    Some(&value_start[..value_end])
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Seal {
            file,
            output,
            note,
            skip_verify,
            passphrase_file,
        } => {
            let output = output.unwrap_or_else(|| {
                let mut p = file.clone();
                p.set_extension("tomb");
                p
            });

            if output.exists() {
                return Err(Error::Format(format!(
                    "output file '{}' already exists, choose a different output path",
                    output.display()
                )));
            }

            let input_meta = fs::metadata(&file).map_err(|e| {
                Error::Io(io::Error::new(
                    e.kind(),
                    format!("{}: {}", file.display(), e),
                ))
            })?;
            if !input_meta.is_file() {
                return Err(Error::Format(format!(
                    "'{}' is not a regular file",
                    file.display()
                )));
            }
            let input_size = input_meta.len();

            // Warn if output filename leaks original name
            let output_name = output.file_name().unwrap_or_default().to_string_lossy();
            let input_name = file.file_name().unwrap_or_default().to_string_lossy();
            if !input_name.is_empty() && output_name.contains(input_name.as_ref()) {
                eprintln!(
                    "Note: output filename '{}' contains the original filename.",
                    output_name
                );
                eprintln!("Consider using -o with a neutral name to avoid leaking metadata.");
            }

            let passphrase = passphrase_for_seal(passphrase_file.as_deref())?;
            let config = cli_config();

            println!("Preparing payload...");
            let mut prepared = crate::prepare_payload(&file, note.as_deref())?;

            println!("Deriving keys (this takes a few seconds)...");
            let pipeline = crate::pipeline::Pipeline::from_cipher_ids(&config.cipher_ids)?;
            let keys = crate::derive_keys(&passphrase, &pipeline, &config.kdf_chain)?;

            println!("Encrypting ({} cipher layers)...", config.cipher_ids.len());
            let header = crate::format::PublicHeader {
                version_major: crate::format::FORMAT_VERSION_MAJOR,
                version_minor: crate::format::FORMAT_VERSION_MINOR,
                kdf_chain: config.kdf_chain.clone(),
                layers: pipeline.layer_descriptors(),
                salt: keys.salt.clone(),
                commitment: keys.commitment.as_bytes().to_vec(),
            };
            crate::encrypt_and_write(&output, &header, &pipeline, &keys.states, &prepared.padded)?;
            prepared.padded.zeroize();

            if !skip_verify {
                if input_size > 100 * 1024 * 1024 {
                    println!("Verifying (use --skip-verify to skip for large files)...");
                } else {
                    println!("Verifying...");
                }
                crate::verify_sealed(&output, &passphrase, &prepared.checksum)?;
            }

            let output_size = fs::metadata(&output)?.len();
            let overhead = output_size as i64 - input_size as i64;
            let sign = if overhead >= 0 { "+" } else { "" };
            println!(
                "Sealed -> {} ({} bytes, was {} bytes, {}{} bytes)",
                output.display(),
                output_size,
                input_size,
                sign,
                overhead
            );
            if skip_verify {
                println!(
                    "Run 'tomb verify {}' to confirm the file is decryptable.",
                    output.display()
                );
            }
            println!("Remember to delete the original file.");
        }
        Command::Open {
            file,
            output,
            passphrase_file,
        } => {
            let passphrase = passphrase_for_open(passphrase_file.as_deref())?;
            let result = crate::open_file(&file, &passphrase).map_err(|e| match e {
                Error::Io(io_err) => Error::Io(io::Error::new(
                    io_err.kind(),
                    format!("{}: {}", file.display(), io_err),
                )),
                other => other,
            })?;
            let output = output.unwrap_or_else(|| PathBuf::from(&result.filename));
            if output.exists() {
                return Err(Error::Format(format!(
                    "output file '{}' already exists, choose a different output path",
                    output.display()
                )));
            }
            fs::write(&output, &result.data)?;
            if let Some(ref note) = result.note {
                println!("Note: {}", note);
            }
            let display_path = output.canonicalize().unwrap_or_else(|_| output.clone());
            println!("Opened -> {}", display_path.display());
        }
        Command::Verify {
            file,
            passphrase_file,
        } => {
            let passphrase = passphrase_for_open(passphrase_file.as_deref())?;
            crate::open_file(&file, &passphrase).map_err(|e| match e {
                Error::Io(io_err) => Error::Io(io::Error::new(
                    io_err.kind(),
                    format!("{}: {}", file.display(), io_err),
                )),
                other => other,
            })?;
            println!("Verified. File is decryptable.");
        }
        Command::Inspect { file } => {
            let header = crate::inspect_file(&file).map_err(|e| match e {
                Error::Io(io_err) => Error::Io(io::Error::new(
                    io_err.kind(),
                    format!("{}: {}", file.display(), io_err),
                )),
                other => other,
            })?;
            println!("tomb file: {}", file.display());
            println!(
                "format version: {}.{}",
                header.version_major, header.version_minor
            );
            println!("KDF chain ({} stages):", header.kdf_chain.len());
            for kdf in &header.kdf_chain {
                let id = kdf.id();
                println!(
                    "  {} (0x{:02x}): {} memory",
                    id.name(),
                    id as u8,
                    kdf.memory_display()
                );
            }
            println!("cipher layers ({}):", header.layers.len());
            for layer in &header.layers {
                println!(
                    "  {} (0x{:02x}), nonce: {} bytes",
                    layer.id.name(),
                    layer.id as u8,
                    layer.nonce_size
                );
            }
        }
        Command::Generate => {
            let words = generate_passphrase(21);

            print!("\x1b[?1049h");
            println!("\nYour passphrase (21 words):\n");
            for chunk in words.chunks(7) {
                println!("  {}", chunk.join(" "));
            }
            println!("\nWrite this down somewhere safe. Press Enter when done...");
            let mut buf = String::new();
            io::stdin().read_line(&mut buf).ok();
            print!("\x1b[?1049l");
        }
        Command::Update => {
            run_update()?;
        }
    }

    Ok(())
}
