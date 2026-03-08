# tomb

Encrypt anything with a passphrase. Recover it decades later.

Governments, corporations, future civilizations, anyone with unlimited resources and unlimited time gets their hands on your encrypted file. tomb is built so that doesn't matter. The ciphertext can be public. The only secret is the passphrase in your head.

## Security Philosophy

Every cryptographic choice in tomb is designed around one goal: **make brute force mathematically impossible, not just impractical.**

Not "would take billions of years." Not "infeasible with current hardware." Impossible. Period.

- **271 bits of passphrase entropy** (21 diceware words). There are ~10^80 atoms in the observable universe. 2^271 is ~10^81. You would need more guesses than there are atoms to try every passphrase, even if each guess took a single Planck time unit (5.39 x 10^-44 seconds), running on every atom simultaneously.
- **2GB memory-hard KDF chain** (scrypt 1GB + Argon2id 1GB). Each guess requires 2GB of RAM. You cannot parallelise with GPUs, ASICs, or any known hardware shortcut. Two different KDF algorithms from different designers, different internal primitives (Salsa20/8 vs Blake2b), so a cryptanalytic break in one still leaves the other standing.
- **Three cipher layers from three algorithm families** (Twofish/Feistel, AES/SP-network, XChaCha20/ARX). Three different design teams, three different mathematical foundations. Every layer is independently authenticated via HMAC-SHA256. A total break of any single algorithm still leaves two layers of 256-bit encryption.

The result: a future civilization that harnesses the energy output of every star in the observable universe, runs for the entire remaining lifespan of the universe, and discovers a breakthrough that breaks one cipher and one KDF, still cannot recover your data.

This is not security theatre. This is the math.

## Usage

```
tomb generate                    # Generate a 21-word passphrase
tomb seal <file>                 # Encrypt a file
tomb seal <file> --skip-verify   # Encrypt without post-seal verification (faster for large files)
tomb open <file.tomb>            # Decrypt a file
tomb verify <file.tomb>          # Confirm a file is decryptable
tomb inspect <file.tomb>         # View public header (no passphrase needed)
```

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/0x63616c/tomb/main/scripts/install.sh | bash
```

Installs to `~/.tomb/bin` and adds it to your PATH. macOS and Linux only (x86_64 and ARM). Run again to update.

## Build from source

```bash
git clone https://github.com/0x63616c/tomb.git
cd tomb
cargo build --release
# Binary at target/release/tomb
```

## How it works

1. You provide (or generate) a 21-word diceware passphrase
2. tomb derives a master key through scrypt (1GB) then Argon2id (1GB), ~5 seconds
3. Per-layer keys are expanded via HKDF-SHA256 with domain separation
4. Your file is encrypted through three layers: Twofish-256-CTR, AES-256-CTR, XChaCha20
5. Each layer is independently authenticated via HMAC-SHA256 (Encrypt-then-MAC)
6. tomb verifies the sealed file by decrypting and comparing checksums (skip with `--skip-verify`)
7. A single `.tomb` file is produced. Store it anywhere.

## Quantum resistance

256-bit symmetric keys are already quantum-resistant. Grover's algorithm halves the effective bit security (271 -> 135 bits), which is still far beyond brute-force range. See [How Long to Crack](docs/how-long-to-crack.md) for the full breakdown.

## Threat model

tomb protects one thing: the contents of your file. It assumes:

- **The attacker has the ciphertext.** The `.tomb` file is public. Posted on GitHub, stored on a USB drive, uploaded to cloud storage, intercepted in transit. Doesn't matter.
- **The attacker has the source code.** Kerckhoffs's principle. The security comes from the passphrase, not from secrecy of the algorithm.
- **The attacker has unlimited time.** Decades, centuries. The math doesn't care.
- **The attacker has nation-state resources.** Custom hardware, data centers, quantum computers (Grover's algorithm halves symmetric key strength, still not enough).

tomb does NOT protect:

- **Metadata.** The filename of the `.tomb` file itself may reveal information. `tax-returns-2024.tomb` tells an attacker what's inside. Use a random filename (e.g., `tomb seal secrets.json -o backup.tomb`).
- **The original file.** tomb does not securely delete the source file. After sealing, delete it yourself. On SSDs, "secure delete" is unreliable. Consider full-disk encryption for your working environment.
- **The passphrase in memory.** tomb zeroes sensitive memory and uses mlock to prevent swapping, but a compromised OS with root access can read process memory. tomb is not a defense against a compromised machine.
- **Availability.** If the `.tomb` file is corrupted or lost, the data is gone. Keep multiple copies. tomb has no error correction (yet).

## Verify a release

Every release includes a `SHA256SUMS` file containing checksums for all binaries.

```
# Download the binary and checksum file
curl -LO https://github.com/0x63616c/tomb/releases/latest/download/tomb-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/0x63616c/tomb/releases/latest/download/SHA256SUMS

# Verify
sha256sum -c SHA256SUMS --ignore-missing
```

On macOS, use `shasum -a 256 -c SHA256SUMS` instead.

## File format

The `.tomb` binary format is fully documented in [FORMAT-SPEC.md](docs/FORMAT-SPEC.md). The spec is precise enough to reimplement a decoder in any language without access to the Rust source code.

If you find a `.tomb` file in 30 years and the tomb binary is gone, the format spec tells you exactly how to decode it.

## Design

- [Design Decisions](docs/DESIGN-DECISIONS.md) - rationale behind every cryptographic choice
- [Format Specification](docs/FORMAT-SPEC.md) - byte-level binary format documentation
- [Requirements](docs/REQUIREMENTS.md) - complete spec
- [Future Ideas](docs/FUTURE.md) - ideas not yet committed to
