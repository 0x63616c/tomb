# tomb

Encrypt anything with a passphrase. Recover it decades later.

Governments, corporations, future civilizations, anyone with unlimited resources and unlimited time gets their hands on your encrypted file. tomb is built so that doesn't matter. The ciphertext can be public. The only secret is the passphrase in your head.

## Security Philosophy

Every cryptographic choice in tomb is designed around one goal: **make brute force mathematically impossible, not just impractical.**

Not "would take mass billion years." Not "infeasible with current hardware." Impossible. Period.

- **271 bits of passphrase entropy** (21 diceware words). There are ~10^80 atoms in the observable universe. 2^271 is ~10^81. You would need more guesses than there are atoms to try every passphrase, even if each guess took a single Planck time unit (5.39 x 10^-44 seconds), running on every atom simultaneously.
- **2GB memory-hard KDF chain** (scrypt 1GB + Argon2id 1GB). Each guess requires 2GB of RAM. You cannot parallelise with GPUs, ASICs, or any known hardware shortcut. Two different KDF algorithms from different designers, different internal primitives (Salsa20/8 vs Blake2b), so a cryptanalytic break in one still leaves the other standing.
- **Three cipher layers from three algorithm families** (Twofish/Feistel, AES/SP-network, XChaCha20/ARX). Three different design teams, three different mathematical foundations. Every layer is independently authenticated via HMAC-SHA256. A total break of any single algorithm still leaves two layers of 256-bit encryption.

The result: a future civilization that harnesses the energy output of every star in the observable universe, runs for the entire remaining lifespan of the universe, and discovers a breakthrough that breaks one cipher and one KDF, still cannot recover your data.

This is not security theatre. This is the math.

## Usage

```
tomb seal <file>          # Encrypt a file
tomb open <file.tomb>     # Decrypt a file
tomb verify <file.tomb>   # Confirm a file is decryptable
tomb inspect <file.tomb>  # View public header (no passphrase needed)
```

## How it works

1. You provide (or generate) a 21-word diceware passphrase
2. tomb derives a master key through scrypt (1GB) then Argon2id (1GB), ~5 seconds
3. Per-layer keys are expanded via HKDF-SHA256 with domain separation
4. Your file is encrypted through three layers: Twofish-256-CTR, AES-256-CTR, XChaCha20
5. Each layer is independently authenticated via HMAC-SHA256 (Encrypt-then-MAC)
6. tomb automatically verifies the sealed file by decrypting and comparing checksums
7. A single `.tomb` file is produced. Store it anywhere.

## Design

See [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md) for the full rationale behind every choice, and [REQUIREMENTS.md](REQUIREMENTS.md) for the complete spec.
