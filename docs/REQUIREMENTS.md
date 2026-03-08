# tomb - Requirements

### Core
1. Encrypt any file with a 21-word diceware passphrase
2. Decrypt a .tomb file back to the original
3. Verify a .tomb file is decryptable without extracting
4. Inspect a .tomb file's public header without passphrase
5. Generate a 21-word diceware passphrase
6. Single static binary, runs on macOS, Linux, Windows

### Key Derivation (chained, 2 layers)
7. scrypt (1GB memory, N=2^20, r=8, p=1) then Argon2id (1GB memory, 4 iterations, 4 parallelism)
8. 32-byte salt from CSPRNG (domain-separated per KDF via HKDF)
9. HKDF-SHA256 to expand master key into per-layer keys (domain separation per label)
10. HMAC-SHA256 key commitment (Invisible Salamanders prevention)

### Encryption (3 cipher layers, uniform Encrypt-then-MAC)
11. Twofish-256-CTR + HMAC-SHA256 (inner), Feistel network, Schneier
12. AES-256-CTR + HMAC-SHA256 (middle), SP-network, Daemen/Rijmen
13. XChaCha20 + HMAC-SHA256 (outer), ARX stream cipher, Bernstein
14. Each layer wraps output in its own envelope (layer ID, nonce, payload length, payload, HMAC tag)
15. PADME padding to hide file size (integer math only)
16. Single-pass encryption (whole file in memory)

### Passphrase
17. Exactly 21 diceware words, enforced (no more, no less)
18. Interactive entry only, no CLI flag, no env var
19. Double entry on seal (type twice to confirm)
20. Built-in generator using CSPRNG + EFF word list (7,776 words)
21. Generated passphrase shown in alternate screen buffer (not in scrollback)
22. Re-enter after generation to prove you wrote it down
23. User-provided passphrases must use EFF diceware words, show which word failed

### File Format
24. Public header: format version, KDF chain (IDs + params), layer chain (IDs + nonce sizes), salt, key commitment
25. Per-layer envelopes: each layer wraps its output with (layer ID, nonce length, nonce, payload length, payload, HMAC tag)
26. Inner encrypted header: filename, original size, SHA-512 checksum, timestamp, tomb version, optional note
27. Forward compatible (match-based lookup, unknown layer/KDF IDs rejected cleanly)
28. Byte-level format spec documented in plaintext alongside the tool

### Security
29. Authenticate before decrypt (each layer's HMAC verified before decryption)
30. Uniform error messages ("decryption failed" for all failures)
31. Memory zeroed via zeroize crate (ALL sensitive values: keys, passphrase, intermediate cipher buffers, padded payload, inner header bytes)
32. All randomness from CSPRNG (OsRng)
33. Constant-time comparisons for all secret-dependent checks
34. Key commitment checked before any decryption attempt
35. mlock() on sensitive memory pages (passphrase, master key, layer keys) to prevent swap-to-disk
36. Atomic file writes (write to .tmp, verify, fs::rename)

### UX
37. `tomb seal <file>` (optional `--note`, optional `-o`)
38. `tomb open <file>` (optional `-o`)
39. `tomb verify <file>`
40. `tomb inspect <file>` (shows public header, no passphrase needed)
41. `tomb generate` (generate a 21-word passphrase, displayed in alternate screen buffer)
42. Automatic verification after seal (re-read, re-derive, decrypt, compare SHA-512)
43. Remind user to delete original after seal
44. ~5 second key derivation (scrypt ~2s + Argon2id ~3s)
45. Warn if output filename leaks original name (e.g. "secrets.json.tomb" reveals content type)

### Architecture
46. Written in Rust
47. Single CipherLayer trait (all layers uniform: CTR/stream encrypt + HMAC-SHA256)
48. Match-based lookup functions (cipher_by_id, kdf_by_id) instead of HashMap registry
49. KDF is trait-based, chaining built at runtime from header's kdf_chain array
50. LayerState bundles encrypt_key + mac_key + nonce per layer (no parallel arrays)
51. CLI enforces policy (21 words, locked params), library accepts params for testing
52. All dependencies vendored into repo

### Rust Crates (vendored)
53. `aes` + `ctr` - AES-256-CTR (RustCrypto)
54. `twofish` + `ctr` - Twofish-256-CTR (RustCrypto)
55. `chacha20` - XChaCha20 stream cipher (RustCrypto)
56. `scrypt` - scrypt KDF (RustCrypto)
57. `argon2` - Argon2id (RustCrypto)
58. `hkdf` + `sha2` - HKDF-SHA256 + SHA-512 (RustCrypto)
59. `hmac` - HMAC-SHA256 per-layer auth + key commitment (RustCrypto)
60. `zeroize` - memory zeroing (RustCrypto)
61. `subtle` - constant-time comparisons (dalek-cryptography)
62. `clap` - CLI parsing
63. `rand` - CSPRNG

### Release
64. GPG-signed releases with checksum file
65. Binary verification instructions in README

### Not Included
66. No post-quantum layer (256-bit symmetric keys already quantum-resistant, document Grover's caveat)
67. No Shamir secret sharing
68. No stdin/stdout mode
69. No crypto configurability from CLI
70. No secure deletion of original file
71. No directory support (tar first)
72. No streaming encryption (whole file must fit in memory)
73. No plausible deniability / hidden volumes
