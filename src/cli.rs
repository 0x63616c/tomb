use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use zeroize::Zeroize;

use crate::key::Passphrase;
use crate::passphrase::{generate::generate_passphrase, validate_passphrase};
use crate::{Error, Result, SealConfig};

#[derive(Parser)]
#[command(
    name = "tomb",
    version,
    about = "Encrypt anything with a passphrase. Recover it decades later."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Encrypt a file
    Seal {
        /// Path to the file to encrypt
        file: PathBuf,
        /// Output path [default: <FILE>.tomb]
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Attach a plaintext note (stored encrypted inside the file)
        #[arg(long)]
        note: Option<String>,
        /// Skip post-seal verification
        #[arg(long)]
        skip_verify: bool,
        /// Read passphrase from a file instead of prompting
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Decrypt a file
    Open {
        /// Path to the .tomb file
        file: PathBuf,
        /// Output path [default: original filename from header]
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Read passphrase from a file instead of prompting
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Verify a file can be decrypted without writing output
    Verify {
        /// Path to the .tomb file
        file: PathBuf,
        /// Read passphrase from a file instead of prompting
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Show public header details (no passphrase needed)
    Inspect {
        /// Path to the .tomb file
        file: PathBuf,
    },
    /// Generate a random 21-word passphrase
    Generate,
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    let pass = rpassword::prompt_password(prompt).map_err(|e| Error::Io(io::Error::other(e)))?;
    Ok(pass)
}

/// Normalize whitespace: trim leading/trailing, collapse multiple spaces to single space.
fn normalize_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn read_passphrase_file(path: &Path) -> Result<Passphrase> {
    let contents = fs::read_to_string(path)?;
    let pass = normalize_whitespace(contents.trim_end_matches('\n'));
    Ok(Passphrase::new(pass.into_bytes()))
}

fn passphrase_for_seal(passphrase_file: Option<&Path>) -> Result<Passphrase> {
    if let Some(path) = passphrase_file {
        let passphrase = read_passphrase_file(path)?;
        validate_passphrase(&String::from_utf8_lossy(passphrase.as_bytes()))?;
        return Ok(passphrase);
    }

    let p1 = prompt_passphrase("Enter passphrase (or press Enter to generate one): ")?;
    let p1 = normalize_whitespace(&p1);

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
        let entered = prompt_passphrase("Passphrase: ")?;
        let entered = normalize_whitespace(&entered);
        let generated = words.join(" ");
        if entered != generated {
            return Err(Error::PassphraseMismatch);
        }
        Ok(Passphrase::new(generated.into_bytes()))
    } else {
        validate_passphrase(&p1)?;
        let p2 = prompt_passphrase("Confirm passphrase: ")?;
        let p2 = normalize_whitespace(&p2);
        if p1 != p2 {
            return Err(Error::PassphraseMismatch);
        }
        Ok(Passphrase::new(p1.into_bytes()))
    }
}

fn passphrase_for_open(passphrase_file: Option<&Path>) -> Result<Passphrase> {
    if let Some(path) = passphrase_file {
        return read_passphrase_file(path);
    }
    let pass = prompt_passphrase("Enter passphrase: ")?;
    let pass = normalize_whitespace(&pass);
    Ok(Passphrase::new(pass.into_bytes()))
}

fn cli_config() -> SealConfig {
    #[cfg(debug_assertions)]
    if std::env::var("TOMB_TEST_PARAMS").is_ok() {
        return SealConfig::test();
    }
    SealConfig::production()
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Seal { file, output, note, skip_verify, passphrase_file } => {
            let output = output.unwrap_or_else(|| {
                let mut p = file.clone();
                p.set_extension("tomb");
                p
            });

            if output.exists() {
                return Err(Error::Format(format!(
                    "output file '{}' already exists, use -o to specify a different path",
                    output.display()
                )));
            }

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

            let input_size = fs::metadata(&file)?.len();

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
                println!("Run 'tomb verify {}' to confirm the file is decryptable.", output.display());
            }
            println!("Remember to delete the original file.");
        }
        Command::Open { file, output, passphrase_file } => {
            let passphrase = passphrase_for_open(passphrase_file.as_deref())?;
            let result = crate::open_file(&file, &passphrase)?;
            let output = output.unwrap_or_else(|| PathBuf::from(&result.filename));
            if output.exists() {
                return Err(Error::Format(format!(
                    "output file '{}' already exists, use -o to specify a different path",
                    output.display()
                )));
            }
            fs::write(&output, &result.data)?;
            println!("Opened -> {}", output.display());
        }
        Command::Verify { file, passphrase_file } => {
            let passphrase = passphrase_for_open(passphrase_file.as_deref())?;
            crate::open_file(&file, &passphrase)?;
            println!("Verified. File is decryptable.");
        }
        Command::Inspect { file } => {
            let header = crate::inspect_file(&file)?;
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
    }

    Ok(())
}
