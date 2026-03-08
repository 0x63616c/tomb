# tomb - Design Decision Log

## D1: No --passphrase flag
**Decision:** Interactive passphrase entry only. No CLI flag, no env var, no file input.
**Why:** If the passphrase ends up in shell history, a script, or process list, the entire security model is broken. This is a last-resort recovery tool, you're typing it in manually. Convenience features that leak secrets have no place here.

## D2: No stdin/stdout mode
**Decision:** File in, .tomb file out. Explicit paths only.
**Why:** If `tomb seal secret.json > backup.tomb` fails midway, you might think you have a backup when you don't. File-to-file lets the tool verify the output before reporting success. For a tool where failure means losing everything, explicit is better than clever.

## D3: Double passphrase entry on seal
**Decision:** Prompt passphrase twice when sealing.
**Why:** Mistyping your passphrase on a backup like this is catastrophic. No recovery possible. Type it twice.

## D4: tomb verify command
**Decision:** `tomb verify backup.tomb` confirms a file is decryptable without extracting.
**Why:** Lets you periodically confirm backups are good and you still remember the passphrase. Peace of mind without exposing plaintext.

## D5: File in, file out
**Decision:** Primary interface is file to file. Directories not in scope (tar first).
**Why:** Keeps the tool simple. One file in, one .tomb file out. Users can tar/zip a directory themselves before sealing.

## D6: Exactly 21-word passphrase
**Decision:** Passphrase must be exactly 21 diceware words. No more, no less.
**Why:** 21 words = ~271 bits of entropy, exceeding the number of atoms in the observable universe (~10^80). No weak passphrases allowed. The tool can generate 21 words for you or you bring your own, but it must be exactly 21.

## D7: Never touch the original file
**Decision:** After sealing, print a reminder to delete the original. Never delete it automatically.
**Why:** Secure deletion is impossible on modern hardware (SSD wear leveling, copy-on-write filesystems). Tomb shouldn't pretend it can do it. The user manages their original files. FileVault/LUKS handles at-rest protection.

## D8: No Shamir secret sharing
**Decision:** Not included. 21 words on paper, stored securely.
**Why:** Adds complexity for marginal benefit. The user stores the passphrase on paper in a secure location. Splitting it into shares adds failure modes (lost shares, confused reconstruction). Keep it simple.

## D9: Alternate screen buffer for passphrase display
**Decision:** When generating a passphrase, display it in the terminal's alternate screen buffer (like vim/less). When the user presses Enter, return to normal screen. Passphrase is not in scrollback.
**Why:** The generated passphrase should not persist in terminal scrollback where someone could find it later.

## D10: Automatic verification after seal
**Decision:** After writing the .tomb file, automatically re-read it from disk, re-derive keys, decrypt, and verify the output matches the original. Report success only after verification passes.
**Why:** A corrupted or incomplete .tomb file discovered years later in an emergency would be catastrophic. Verify at seal time, not open time.

## D11: No configurability for crypto
**Decision:** All cryptographic parameters are locked. No CLI flags for algorithm choice, KDF params, layer count, or key sizes. Version the format instead.
**Why:** Follows age/WireGuard/Signal philosophy. Cryptographic agility is an anti-pattern that enables downgrade attacks and user misconfiguration. We make the right choices so users don't have to. Internal library accepts params for testing only.

## D12: Three cipher layers, uniform Encrypt-then-MAC
**Decision:** Twofish-256-CTR + HMAC-SHA256, AES-256-CTR + HMAC-SHA256, XChaCha20 + HMAC-SHA256. All three layers use the same pattern: encrypt with the stream/CTR cipher, then authenticate with HMAC-SHA256.
**Why:** Three different algorithm families (Feistel, SP-network, ARX), three different design teams (Schneier, Daemen/Rijmen, Bernstein). If one algorithm is ever broken, the other two still protect the data. Every layer is independently authenticated, so layer order doesn't matter. Each layer alone is a complete, secure encryption system. One trait, one auth mechanism, three interchangeable ciphers. Replaced XChaCha20-Poly1305 with XChaCha20 + HMAC-SHA256 so all layers are uniform. Poly1305 is faster but HMAC-SHA256 overhead is negligible compared to the 5-second KDF.

## D13: Uniform HMAC-SHA256 over mixed AEAD
**Decision:** All three layers use HMAC-SHA256 for authentication instead of Poly1305 on the outer layer and nothing on the inner layers.
**Why:** Every layer should be equally secure on its own. With mixed auth (only the outer layer authenticates), layer order matters and inner layers are vulnerable to tampering if isolated. With uniform Encrypt-then-MAC, any single layer is a complete encryption system. This also simplifies the codebase: one trait instead of separate Encrypt and Seal traits, one authentication primitive everywhere. The HMAC key for each layer is derived separately via HKDF with its own label (e.g. "tomb-twofish-256-ctr-mac"), independent from the encryption key.

## D14: Chained KDF (scrypt -> Argon2id)
**Decision:** Two KDFs chained: scrypt (1GB, Salsa20/8 core) then Argon2id (1GB, Blake2b core). Different algorithm families for the KDF layer, same principle as cipher layering.
**Why:** If a flaw is found in Argon2id that lets attackers skip the memory-hard computation, scrypt still protects the passphrase. Two different memory-hard functions from different designers using different internal math. ~5 seconds total.

## D15: Per-layer envelopes
**Decision:** Each cipher layer wraps its output with a small header (layer ID, nonce length, nonce, payload length, payload, HMAC tag). Layers are nested like an onion.
**Why:** Makes each layer fully self-contained and independently testable. Adding a 4th layer in a future version just wraps another envelope around the outside. Debugging can peel one layer at a time. Clean abstraction.

## D16: tomb inspect command
**Decision:** `tomb inspect file.tomb` reads and displays the public header without requiring a passphrase.
**Why:** Useful for debugging during development and for users to confirm what's inside a .tomb file without decrypting.

## D17: SHA-512 checksum in inner header
**Decision:** Store SHA-512 hash of original plaintext in the encrypted inner header. Verify after full decryption.
**Why:** End-to-end integrity check independent of all cipher layers. Catches bugs in our own decryption pipeline, not attacker tampering (that's what per-layer HMAC is for). If we ever change algorithms in a future format version, the checksum catches any decryption pipeline bugs.

## D18: Library vs CLI separation
**Decision:** Library accepts all params (for testing). CLI enforces policy (21 words, 1GB KDFs, locked cipher stack). Tests use tiny params and run in milliseconds.
**Why:** Testability without compromising production security. The CLI is the policy layer, the library is the engine.

## D19: Binary file format
**Decision:** .tomb files are binary, not text/base64 encoded.
**Why:** Compact (no encoding overhead), no encoding/decoding bugs. Use `tomb inspect` for human-readable header info.

## D20: Public header is not secret
**Decision:** The public header (algorithms, KDF params, version) is unencrypted. This is fine because the tool is open source and every .tomb file uses the same config.
**Why:** Kerckhoffs's principle. The system is secure even if the attacker knows everything except the passphrase. Hiding algorithms in the header would be security through obscurity. The source code is public.
