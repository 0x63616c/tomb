use std::io::{self, Write};
use std::path::PathBuf;
use std::fs;

use clap::{Parser, Subcommand};

use crate::{Error, Result};
use crate::key::Passphrase;
use crate::passphrase::{validate_passphrase, generate::generate_passphrase};

#[derive(Parser)]
#[command(name = "tomb", about = "Encrypt anything with a passphrase. Recover it decades later.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Encrypt a file
    Seal {
        file: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Decrypt a file
    Open {
        file: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Confirm a file is decryptable
    Verify {
        file: PathBuf,
    },
    /// View public header (no passphrase needed)
    Inspect {
        file: PathBuf,
    },
    /// Generate a 21-word passphrase
    Generate,
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    let pass = rpassword::prompt_password(prompt)
        .map_err(|e| Error::Io(io::Error::other(e)))?;
    Ok(pass)
}

fn prompt_passphrase_for_seal() -> Result<Passphrase> {
    println!("  1. Generate a secure passphrase (21 words)");
    println!("  2. Enter your own passphrase");
    print!("Choice: ");
    io::stdout().flush().ok();

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)
        .map_err(Error::Io)?;

    match choice.trim() {
        "1" => {
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
            let generated = words.join(" ");
            if entered != generated {
                return Err(Error::PassphraseMismatch);
            }
            Ok(Passphrase::new(generated.into_bytes()))
        }
        "2" => {
            let p1 = prompt_passphrase("Enter passphrase (21 words from the EFF diceware list): ")?;
            validate_passphrase(&p1)?;
            let p2 = prompt_passphrase("Confirm passphrase: ")?;
            if p1 != p2 {
                return Err(Error::PassphraseMismatch);
            }
            Ok(Passphrase::new(p1.into_bytes()))
        }
        _ => Err(Error::Format("invalid choice".into())),
    }
}

fn prompt_passphrase_for_open() -> Result<Passphrase> {
    let pass = prompt_passphrase("Enter passphrase: ")?;
    Ok(Passphrase::new(pass.into_bytes()))
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Seal { file, output, note } => {
            let output = output.unwrap_or_else(|| {
                let mut p = file.clone();
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                p.set_file_name(format!("{name}.tomb"));
                p
            });

            // Warn if output filename leaks original name
            let output_name = output.file_name().unwrap_or_default().to_string_lossy();
            let input_name = file.file_name().unwrap_or_default().to_string_lossy();
            if !input_name.is_empty() && output_name.contains(input_name.as_ref()) {
                eprintln!("Note: output filename '{}' contains the original filename.", output_name);
                eprintln!("Consider using -o with a neutral name to avoid leaking metadata.");
            }

            let passphrase = prompt_passphrase_for_seal()?;
            crate::seal(&file, &output, &passphrase, note.as_deref())?;

            let meta = fs::metadata(&output)?;
            println!("Sealed -> {} ({} bytes)", output.display(), meta.len());
            println!("Remember to delete the original file.");
        }
        Command::Open { file, output } => {
            let passphrase = prompt_passphrase_for_open()?;
            let result = crate::open_file(&file, &passphrase)?;
            let output = output.unwrap_or_else(|| PathBuf::from(&result.filename));
            fs::write(&output, &result.data)?;
            println!("Opened -> {}", output.display());
        }
        Command::Verify { file } => {
            let passphrase = prompt_passphrase_for_open()?;
            crate::open_file(&file, &passphrase)?;
            println!("Verified. File is decryptable.");
        }
        Command::Inspect { file } => {
            let header = crate::inspect_file(&file)?;
            println!("tomb file: {}", file.display());
            println!("format version: {}.{}", header.version_major, header.version_minor);
            println!("KDF chain ({} stages):", header.kdf_chain.len());
            for kdf in &header.kdf_chain {
                let name = match kdf.id {
                    0x10 => "scrypt",
                    0x11 => "argon2id",
                    _ => "unknown",
                };
                println!("  {name} (0x{:02x}): {}MB memory, {} iterations, {} parallelism",
                    kdf.id, kdf.memory_mb, kdf.iterations, kdf.parallelism);
            }
            println!("cipher layers ({}):", header.layers.len());
            for layer in &header.layers {
                let name = match layer.id {
                    0x20 => "twofish-256-ctr + hmac-sha256",
                    0x21 => "aes-256-ctr + hmac-sha256",
                    0x22 => "xchacha20 + hmac-sha256",
                    _ => "unknown",
                };
                println!("  {name} (0x{:02x}), nonce: {} bytes", layer.id, layer.nonce_size);
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
