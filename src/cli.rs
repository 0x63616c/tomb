use std::io;
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

/// Normalize whitespace: trim leading/trailing, collapse multiple spaces to single space.
fn normalize_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn prompt_passphrase_for_seal() -> Result<Passphrase> {
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

fn prompt_passphrase_for_open() -> Result<Passphrase> {
    let pass = prompt_passphrase("Enter passphrase: ")?;
    let pass = normalize_whitespace(&pass);
    Ok(Passphrase::new(pass.into_bytes()))
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Seal { file, output, note } => {
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
                eprintln!("Note: output filename '{}' contains the original filename.", output_name);
                eprintln!("Consider using -o with a neutral name to avoid leaking metadata.");
            }

            let input_size = fs::metadata(&file)?.len();

            let passphrase = prompt_passphrase_for_seal()?;
            println!("Deriving keys (this takes a few seconds)...");
            crate::seal(&file, &output, &passphrase, note.as_deref())?;

            let output_size = fs::metadata(&output)?.len();
            let overhead = output_size as i64 - input_size as i64;
            let sign = if overhead >= 0 { "+" } else { "" };
            println!("Sealed -> {} ({} bytes, was {} bytes, {}{} bytes)",
                output.display(), output_size, input_size, sign, overhead);
            println!("Remember to delete the original file.");
        }
        Command::Open { file, output } => {
            let passphrase = prompt_passphrase_for_open()?;
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
                let id = kdf.id();
                println!("  {} (0x{:02x}): {} memory",
                    id.name(), id as u8, kdf.memory_display());
            }
            println!("cipher layers ({}):", header.layers.len());
            for layer in &header.layers {
                println!("  {} (0x{:02x}), nonce: {} bytes",
                    layer.id.name(), layer.id as u8, layer.nonce_size);
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
