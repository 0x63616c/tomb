# Tomb Binary Format Specification

**Format version:** 1.0
**Date:** 2026-03-07
**Status:** Stable

This document specifies the byte-level binary format of `.tomb` files produced by the `tomb seal` command. It is intended to be a complete, standalone reference sufficient to implement a compatible decoder in any programming language, without access to the Rust source code.

All multi-byte integers are **little-endian** unless otherwise noted.

---

## 1. File Structure Overview

A `.tomb` file consists of two regions laid out sequentially:

```
[Public Header][Sealed Body]
```

- **Public Header** is readable without decryption. It contains all parameters needed to derive keys and decrypt the file.
- **Sealed Body** is the encrypted payload, structured as three nested layer envelopes (outermost first).

---

## 2. Public Header

### 2.1 Layout

```
Offset  Size   Field
------  ----   -----
0       5      Magic bytes: "TOMB\n" (0x54 0x4F 0x4D 0x42 0x0A)
5       1      Version major (u8)
6       1      Version minor (u8)
7       1      KDF count (u8)
8       var    KDF parameters (repeated kdf_count times, variable size each)
var     1      Layer count (u8)
var     var    Layer descriptors (repeated layer_count times, 2 bytes each)
var     32     Salt (random bytes)
var     32     Key commitment (HMAC-SHA256 tag)
var     4      Header length (u32 LE, total byte count of the entire public header including this field)
```

The header length field at the end allows a reader to locate the start of the sealed body without parsing every field. The value of `header_length` equals the byte offset where the sealed body begins.

### 2.2 Version

Version 1.0 is encoded as:

```
Byte 5: 0x01  (major)
Byte 6: 0x00  (minor)
```

A decoder MUST reject files with an unrecognized major version. Minor version differences within the same major version indicate backward-compatible additions.

### 2.3 Magic Bytes

The 5-byte magic `TOMB\n` (hex `54 4F 4D 42 0A`) identifies the file format. The trailing newline (`0x0A`) ensures that if a user accidentally `cat`s the file, the terminal does not attempt to interpret the binary header on the same line as a shell prompt.

---

## 3. KDF Parameters

Each KDF parameter block begins with a 1-byte KDF identifier, followed by algorithm-specific fields.

### 3.1 KDF Identifiers

| ID     | Algorithm    |
|--------|-------------|
| `0x01` | scrypt      |
| `0x02` | Argon2id    |

Any other ID is invalid and MUST cause the decoder to reject the file.

### 3.2 Scrypt Parameters (10 bytes)

```
Offset  Size  Field
------  ----  -----
0       1     KDF ID: 0x01
1       1     log_n (u8) -- log2 of the cost parameter N
2       4     r (u32 LE) -- block size
6       4     p (u32 LE) -- parallelism
```

The scrypt cost parameter `N` is computed as `2^log_n`. The memory requirement in bytes is `N * r * 128`.

**Production values:** `log_n=20, r=8, p=1` (1 GB memory).
**Test values:** `log_n=10, r=8, p=1` (1 MB memory).

### 3.3 Argon2id Parameters (13 bytes)

```
Offset  Size  Field
------  ----  -----
0       1     KDF ID: 0x02
1       4     memory_kib (u32 LE) -- memory cost in kibibytes (KiB)
5       4     iterations (u32 LE) -- time cost (number of passes)
9       4     parallelism (u32 LE) -- degree of parallelism (lanes)
```

The Argon2 variant is always Argon2id (hybrid data-dependent and data-independent addressing). The version is always 0x13 (v19, the current Argon2 specification version). Output length is always 32 bytes.

**Production values:** `memory_kib=1048576, iterations=4, parallelism=4` (1 GB memory).
**Test values:** `memory_kib=1024, iterations=1, parallelism=1` (1 MB memory).

---

## 4. Layer Descriptors

Each layer descriptor is 2 bytes:

```
Offset  Size  Field
------  ----  -----
0       1     Cipher ID (u8)
1       1     Nonce size in bytes (u8)
```

### 4.1 Cipher Identifiers

| ID     | Algorithm               | Nonce Size |
|--------|------------------------|------------|
| `0x01` | Twofish-256-CTR        | 16 bytes   |
| `0x02` | AES-256-CTR            | 16 bytes   |
| `0x03` | XChaCha20              | 24 bytes   |

Cipher IDs and KDF IDs occupy separate namespaces. The value `0x01` for a cipher ID (Twofish) is unrelated to `0x01` for a KDF ID (scrypt).

Any unrecognized cipher ID MUST cause the decoder to reject the file.

All cipher layers use 256-bit (32-byte) encryption keys. All layers are authenticated with HMAC-SHA256 using independent 256-bit (32-byte) MAC keys. The Encrypt-then-MAC construction is uniform across all layers.

### 4.2 Standard Configuration

The standard tomb configuration uses 2 KDFs and 3 cipher layers, always in this order:

1. KDF chain: scrypt, then Argon2id
2. Cipher layers: Twofish (layer 0), AES (layer 1), XChaCha20 (layer 2)

---

## 5. Salt and Key Commitment

### 5.1 Salt

32 bytes of cryptographically random data generated from the OS CSPRNG at seal time. Used as input to the KDF chain for per-layer salt derivation (see Section 8).

### 5.2 Key Commitment

32 bytes. This is an HMAC-SHA256 tag that commits to the master key. It allows the decoder to verify that the passphrase is correct before attempting decryption, and it prevents Invisible Salamanders attacks (where a single ciphertext decrypts to two different plaintexts under two different keys).

Computation:

```
commitment = HMAC-SHA256(key=master_key, message=b"tomb-key-commitment")
```

The decoder MUST verify the key commitment before proceeding with decryption. If verification fails, the decoder MUST return a generic "decryption failed" error without distinguishing it from other authentication failures.

---

## 6. Public Header Example (Standard Production Config)

For the standard production configuration with 2 KDFs and 3 cipher layers:

```
Offset  Hex                                          Description
------  ---                                          -----------
0-4     54 4F 4D 42 0A                               Magic "TOMB\n"
5       01                                           Version major = 1
6       00                                           Version minor = 0
7       02                                           KDF count = 2
8       01                                           KDF[0]: scrypt (0x01)
9       14                                           KDF[0]: log_n = 20
10-13   08 00 00 00                                  KDF[0]: r = 8
14-17   01 00 00 00                                  KDF[0]: p = 1
18      02                                           KDF[1]: argon2id (0x02)
19-22   00 00 10 00                                  KDF[1]: memory_kib = 1048576
23-26   04 00 00 00                                  KDF[1]: iterations = 4
27-30   04 00 00 00                                  KDF[1]: parallelism = 4
31      03                                           Layer count = 3
32-33   01 10                                        Layer[0]: Twofish (0x01), nonce_size=16
34-35   02 10                                        Layer[1]: AES (0x02), nonce_size=16
36-37   03 18                                        Layer[2]: XChaCha (0x03), nonce_size=24
38-69   XX XX .. XX                                  Salt (32 random bytes)
70-101  XX XX .. XX                                  Key commitment (32 bytes)
102-105 6A 00 00 00                                  Header length = 106
```

**Total public header size (standard config): 106 bytes.**

The sealed body begins at byte offset 106.

Note: Header length is variable. Different KDF configurations or different numbers of cipher layers produce different header sizes. The `header_length` field at the end is the authoritative source for where the header ends.

---

## 7. Sealed Body

The sealed body is a chain of nested layer envelopes. In the standard 3-layer configuration:

```
XChaCha envelope {
  AES envelope {
    Twofish envelope {
      padded payload (inner header + plaintext + padding)
    }
  }
}
```

**Seal order (encryption):** Twofish encrypts the padded payload first. AES encrypts the Twofish envelope second. XChaCha encrypts the AES envelope third. The outermost envelope in the file is always the last cipher layer.

**Open order (decryption):** XChaCha decrypts first (outermost). AES decrypts second. Twofish decrypts third (innermost). After Twofish decryption, the padded payload is recovered.

### 7.1 Layer Envelope Format

Each envelope is a contiguous byte sequence:

```
Offset  Size          Field
------  ----          -----
0       1             Layer ID (u8, same as cipher ID from Section 4.1)
1       1             Nonce length (u8)
2       nonce_len     Nonce (random bytes, generated at seal time)
var     8             Payload length (u64 LE)
var     payload_len   Payload (encrypted ciphertext)
var     32            MAC tag (HMAC-SHA256)
```

### 7.2 HMAC Computation

The MAC tag authenticates the envelope using Encrypt-then-MAC. The HMAC input is the concatenation of three fields in order:

```
HMAC-SHA256(key=mac_key, message = layer_id || nonce || payload)
```

Where:
- `layer_id` is the single byte cipher ID (e.g., `0x01` for Twofish)
- `nonce` is the full nonce bytes (not prefixed with length)
- `payload` is the encrypted ciphertext bytes (not prefixed with length)
- `||` denotes concatenation

The MAC key is a 32-byte key derived independently from the encryption key (see Section 8.2).

### 7.3 MAC Verification

During decryption, the decoder MUST verify the MAC tag before decrypting the payload. Verification MUST use constant-time comparison. If any layer's MAC fails, the decoder MUST return a generic "decryption failed" error.

### 7.4 Envelope Size

The total size of a single envelope for payload of `P` bytes with nonce of `N` bytes:

```
envelope_size = 1 + 1 + N + 8 + P + 32 = P + N + 42
```

For the standard 3-layer configuration with an innermost padded payload of `P` bytes:

- Twofish envelope: `P + 16 + 42 = P + 58` bytes
- AES envelope: `(P + 58) + 16 + 42 = P + 116` bytes
- XChaCha envelope: `(P + 116) + 24 + 42 = P + 182` bytes

The total sealed body size is `P + 182` bytes, where `P` is the padded payload size.

---

## 8. Key Derivation

### 8.1 KDF Chain

The KDF chain transforms the passphrase into a 32-byte master key through sequential application of multiple KDFs. Each KDF in the chain receives a unique salt derived from the file's random salt.

**Algorithm:**

1. Let `input = passphrase_bytes` (UTF-8 encoded passphrase).
2. Compute a pseudo-random key: `prk = HKDF-SHA256-Extract(salt=None, ikm=file_salt)`.
   - "None" means no salt is provided to HKDF-Extract. The HKDF implementation uses a zero-filled salt of hash length (32 bytes for SHA-256).
3. For each KDF in the chain (in order):
   a. Derive a per-KDF salt:
      ```
      label = "tomb-kdf-{kdf_id:02x}-salt"
      kdf_salt = HKDF-SHA256-Expand(prk, info=label, length=32)
      ```
      For scrypt (ID 0x01): label = `"tomb-kdf-01-salt"` (16 bytes ASCII).
      For Argon2id (ID 0x02): label = `"tomb-kdf-02-salt"` (16 bytes ASCII).
   b. Compute: `output = KDF(input, kdf_salt, params)`, producing 32 bytes.
   c. Set `input = output` for the next KDF in the chain.
4. The final 32-byte output is the **master key**.

### 8.2 Per-Layer Key Expansion

Each cipher layer requires two independent 32-byte keys (encryption key and MAC key). These are derived from the master key using HKDF-SHA256.

**Algorithm:**

1. Compute a pseudo-random key: `prk = HKDF-SHA256-Extract(salt=None, ikm=master_key)`.
   - Again, "None" means no salt, so HKDF uses a zero-filled salt of 32 bytes.
2. For each cipher layer:
   a. Derive the encryption key:
      ```
      encrypt_key = HKDF-SHA256-Expand(prk, info=encrypt_label, length=32)
      ```
   b. Derive the MAC key:
      ```
      mac_key = HKDF-SHA256-Expand(prk, info=mac_label, length=32)
      ```

The labels for each cipher layer are fixed ASCII strings:

| Cipher    | Encrypt Label              | MAC Label                      |
|-----------|---------------------------|--------------------------------|
| Twofish   | `"tomb-twofish-256-ctr"`   | `"tomb-twofish-256-ctr-mac"`   |
| AES       | `"tomb-aes-256-ctr"`       | `"tomb-aes-256-ctr-mac"`       |
| XChaCha20 | `"tomb-xchacha20"`         | `"tomb-xchacha20-mac"`         |

Each layer also requires a random nonce generated from the OS CSPRNG at seal time. The nonce size matches the cipher (16 bytes for Twofish and AES, 24 bytes for XChaCha20). Nonces are stored inside the layer envelope, not derived from the key material.

---

## 9. Padded Payload

The padded payload is the innermost plaintext that gets encrypted through the 3-layer pipeline. Its structure is:

```
[Inner Header][Original File Bytes][Padding]
```

### 9.1 PADME Padding

PADME padding obscures the exact size of the original file. The padding algorithm operates on the total size of `inner_header + plaintext` (call this `n`):

- If `n <= 256`: pad to exactly 256 bytes.
- If `n > 256`:
  1. `e = floor(log2(n))` (the position of the highest set bit)
  2. `s = floor(log2(e)) + 1`
  3. `last_bits = e - s`
  4. `bit_mask = (1 << last_bits) - 1`
  5. `padded_length = (n + bit_mask) & ~bit_mask`

The padding bytes are filled with random data from the OS CSPRNG. The original size is stored in the inner header, so the decoder knows where the plaintext ends. Padding bytes are not authenticated individually. They are part of the encrypted payload and are covered by each layer's HMAC.

### 9.2 PADME Properties

- Minimum output: 256 bytes
- Maximum overhead: approximately 12% for inputs larger than 256 bytes
- Output is always a power-of-two-aligned value, leaking at most `O(log log n)` bits about the input size
- Uses integer arithmetic only (no floating point)

---

## 10. Inner Header

The inner header is stored inside the encrypted payload, immediately before the original file bytes. It is only accessible after full decryption.

### 10.1 Layout

```
Offset  Size          Field
------  ----          -----
0       2             Filename length (u16 LE)
2       var           Filename (UTF-8 encoded bytes)
var     8             Original file size in bytes (u64 LE)
var     64            SHA-512 checksum of the original file
var     8             Sealed-at timestamp (u64 LE, Unix epoch seconds)
var     2             Tomb version string length (u16 LE)
var     var           Tomb version string (UTF-8, e.g. "0.1.0")
var     1             Has-note flag (u8: 0x00=no note, 0x01=has note)
```

If `has_note == 0x01`, the following fields are appended:

```
var     2             Note length (u16 LE)
var     var           Note text (UTF-8 encoded bytes)
```

If `has_note == 0x00`, no further fields follow.

### 10.2 Field Details

**Filename:** The basename of the original file (e.g., `"secrets.json"`), not a full path. Maximum length is 65,535 bytes (u16 limit). The filename is used when writing the decrypted output.

**Original file size:** The exact byte count of the original plaintext file. Used to strip PADME padding after decryption: the decoder reads `original_size` bytes starting immediately after the inner header.

**SHA-512 checksum:** 64 bytes. A SHA-512 hash of the original plaintext file contents. This is an integrity check against the decoder's own pipeline bugs, not a cryptographic authentication mechanism (the HMAC layers handle authentication). Verification MUST use constant-time comparison.

**Sealed-at timestamp:** Unix epoch timestamp (seconds since 1970-01-01T00:00:00Z) of when the file was sealed. Informational only. A value of 0 indicates the system clock was unavailable.

**Tomb version:** The version string of the `tomb` binary that created the file (e.g., `"0.1.0"`). Informational only.

**Note:** An optional user-provided text annotation. If present, it is stored as UTF-8.

### 10.3 Inner Header Example

For a file named `"secrets.json"` (12 bytes), file size 4096, sealed at Unix timestamp 1709827200, tomb version `"0.1.0"`, with note `"backup"`:

```
Offset  Hex                                    Description
------  ---                                    -----------
0-1     0C 00                                  Filename length = 12
2-13    73 65 63 72 65 74 73 2E 6A 73 6F 6E    "secrets.json"
14-21   00 10 00 00 00 00 00 00                Original size = 4096
22-85   XX XX .. XX                            SHA-512 checksum (64 bytes)
86-93   00 8A E6 65 00 00 00 00                Sealed-at = 1709827200
94-95   05 00                                  Version length = 5
96-100  30 2E 31 2E 30                         "0.1.0"
101     01                                     Has note = yes
102-103 06 00                                  Note length = 6
104-109 62 61 63 6B 75 70                      "backup"
```

---

## 11. Decryption Procedure

A complete decoder MUST perform these steps in order:

1. **Read magic bytes.** Verify the first 5 bytes are `54 4F 4D 42 0A`. Reject if not.

2. **Read version.** Check major version compatibility. Reject unknown major versions.

3. **Parse public header.** Read KDF parameters, layer descriptors, salt, key commitment, and header length. Verify the header length field matches the actual number of bytes consumed.

4. **Derive master key.** Using the passphrase (UTF-8 bytes), salt, and KDF parameters from the header, execute the KDF chain as described in Section 8.1.

5. **Verify key commitment.** Compute `HMAC-SHA256(master_key, b"tomb-key-commitment")` and compare (constant-time) with the stored commitment. If they do not match, return "decryption failed".

6. **Expand per-layer keys.** Using HKDF-SHA256 as described in Section 8.2, derive encryption and MAC keys for each cipher layer. Generate or read nonces from the envelopes (during decryption, nonces come from the envelope, not from HKDF).

7. **Peel layer envelopes.** Starting from the outermost layer (last in the layer descriptor list), for each layer in reverse order:
   a. Parse the layer envelope (Section 7.1).
   b. Verify the HMAC tag using constant-time comparison (Section 7.2). Reject on failure.
   c. Decrypt the payload using the layer's encryption key and the nonce from the envelope.
   d. The decrypted payload is the input for the next (inner) layer, or the padded payload if this is the innermost layer.

8. **Parse inner header.** Deserialize the inner header from the decrypted padded payload (Section 10).

9. **Extract plaintext.** Read `original_size` bytes starting immediately after the inner header. Discard remaining bytes (PADME padding).

10. **Verify SHA-512 checksum.** Compute SHA-512 of the extracted plaintext and compare (constant-time) with the checksum in the inner header. Reject on mismatch.

11. **Return plaintext** and metadata (filename, note, etc.).

---

## 12. Cipher Details

All three cipher layers operate as stream ciphers in CTR mode. The encryption and decryption operations are identical (XOR with keystream).

### 12.1 Twofish-256-CTR

- Algorithm: Twofish block cipher in CTR mode
- Key size: 256 bits (32 bytes)
- Nonce/IV size: 128 bits (16 bytes)
- Block size: 128 bits
- The nonce is used as the initial counter value

### 12.2 AES-256-CTR

- Algorithm: AES block cipher in CTR mode
- Key size: 256 bits (32 bytes)
- Nonce/IV size: 128 bits (16 bytes)
- Block size: 128 bits
- The nonce is used as the initial counter value

### 12.3 XChaCha20

- Algorithm: XChaCha20 stream cipher (extended-nonce variant of ChaCha20)
- Key size: 256 bits (32 bytes)
- Nonce size: 192 bits (24 bytes)
- This is the raw stream cipher, NOT the AEAD construction (XChaCha20-Poly1305). Authentication is handled separately by HMAC-SHA256.

---

## 13. Security Properties

- **Three independent cipher layers.** Compromise of any one cipher algorithm does not reveal plaintext.
- **Chained KDF.** The passphrase is processed through scrypt then Argon2id. An attacker must break both KDFs.
- **Encrypt-then-MAC on every layer.** Each layer is independently authenticated with HMAC-SHA256 before decryption.
- **Key commitment.** Prevents multi-key attacks (Invisible Salamanders) where a ciphertext could decrypt validly under multiple keys.
- **Constant-time comparisons.** All secret-dependent comparisons (MAC verification, key commitment, checksum) use constant-time operations to prevent timing side channels.
- **Independent keys per layer.** HKDF domain separation ensures that encryption keys and MAC keys for different layers are cryptographically independent.
- **Random nonces per layer.** Each cipher layer uses an independently generated random nonce from the OS CSPRNG.
- **PADME padding.** Obscures exact file size, leaking at most `O(log log n)` bits about the plaintext length.
- **Uniform error messages.** A single "decryption failed" error is returned for all authentication and decryption failures, preventing error oracle attacks.

---

## 14. File Size Calculations

For a plaintext file of `F` bytes, with inner header of `H` bytes:

1. **Inner header size (H):** Variable. Minimum is `2 + 0 + 8 + 64 + 8 + 2 + 0 + 1 = 85` bytes (empty filename, empty version, no note). Typical size with a short filename and version string is approximately 100-110 bytes.

2. **Pre-padding size:** `H + F` bytes.

3. **Padded payload size (P):** `padme_length(H + F)` bytes. Minimum 256 bytes.

4. **Sealed body size:** `P + 182` bytes (for 3 standard layers, see Section 7.4).

5. **Total file size:** `header_length + P + 182` bytes. With the standard header (106 bytes): `106 + P + 182 = P + 288` bytes.

---

## 15. Passphrase Requirements

The CLI enforces a minimum of 21 words from the EFF diceware word list (7,776 words), providing approximately 271 bits of entropy. This is a CLI policy, not a format constraint. The binary format itself places no restrictions on passphrase length or content. A compatible decoder may accept any passphrase.

---

## 16. Implementation Notes

### 16.1 Endianness

All multi-byte integers (u16, u32, u64) are little-endian throughout the entire format, in both the public header and the inner header.

### 16.2 String Encoding

All strings (filename, tomb version, note) are UTF-8 encoded. Length prefixes give the byte length, not the character count.

### 16.3 HKDF Details

This format uses HKDF as defined in RFC 5869, instantiated with HMAC-SHA256.

- **HKDF-Extract** takes a salt and input keying material (IKM), producing a pseudo-random key (PRK).
- **HKDF-Expand** takes a PRK, an info string, and a desired output length, producing the derived key.

When "salt=None" is specified, the HKDF implementation MUST use a zero-filled byte string of length equal to the hash output size (32 bytes for SHA-256) as the salt input to HMAC, per RFC 5869 Section 2.2.

### 16.4 Atomic Writes

The `tomb seal` command writes to a temporary file (`.tomb.tmp` extension) and atomically renames it to the final path. This prevents partial writes from corrupting an existing `.tomb` file. This is a CLI behavior, not a format concern.

### 16.5 Duplicate Layer Rejection

A valid `.tomb` file MUST NOT contain duplicate cipher IDs in its layer descriptor list. A decoder SHOULD reject files with duplicate cipher layers.

---

## 17. Complete Byte Map (Reference Example)

This example shows every byte of a `.tomb` file created with the standard production configuration, sealing a 4,096-byte file named `"data.bin"` with no note. All random values are shown as `XX`.

### Public Header (106 bytes)

```
Offset    Hex                         Description
--------  --------------------------  ----------------------------------
0x0000    54 4F 4D 42 0A              Magic "TOMB\n"
0x0005    01                          Version major
0x0006    00                          Version minor
0x0007    02                          KDF count
0x0008    01                          Scrypt ID
0x0009    14                          log_n = 20
0x000A    08 00 00 00                 r = 8
0x000E    01 00 00 00                 p = 1
0x0012    02                          Argon2id ID
0x0013    00 00 10 00                 memory_kib = 1048576
0x0017    04 00 00 00                 iterations = 4
0x001B    04 00 00 00                 parallelism = 4
0x001F    03                          Layer count
0x0020    01 10                       Twofish, nonce=16
0x0022    02 10                       AES, nonce=16
0x0024    03 18                       XChaCha, nonce=24
0x0026    XX*32                       Salt (32 bytes)
0x0046    XX*32                       Key commitment (32 bytes)
0x0066    6A 00 00 00                 Header length = 106
```

### Sealed Body (starts at 0x006A)

```
--- XChaCha envelope (outermost) ---
0x006A    03                          Layer ID = XChaCha
0x006B    18                          Nonce length = 24
0x006C    XX*24                       Nonce (24 bytes)
0x0084    LL LL LL LL LL LL LL LL     Payload length (u64 LE)
0x008C    [encrypted AES envelope]    Payload bytes
...       XX*32                       HMAC-SHA256 tag

  --- AES envelope (middle, encrypted inside XChaCha payload) ---
  +0x00   02                          Layer ID = AES
  +0x01   10                          Nonce length = 16
  +0x02   XX*16                       Nonce (16 bytes)
  +0x12   LL LL LL LL LL LL LL LL     Payload length (u64 LE)
  +0x1A   [encrypted Twofish env]     Payload bytes
  ...     XX*32                       HMAC-SHA256 tag

    --- Twofish envelope (innermost, encrypted inside AES payload) ---
    +0x00  01                         Layer ID = Twofish
    +0x01  10                         Nonce length = 16
    +0x02  XX*16                      Nonce (16 bytes)
    +0x12  LL LL LL LL LL LL LL LL    Payload length (u64 LE)
    +0x1A  [encrypted padded payload] Payload bytes
    ...    XX*32                       HMAC-SHA256 tag

      --- Padded payload (after full decryption) ---
      +0x00  08 00                    Filename length = 8
      +0x02  64 61 74 61 2E 62 69 6E  "data.bin"
      +0x0A  00 10 00 00 00 00 00 00  Original size = 4096
      +0x12  XX*64                    SHA-512 checksum
      +0x52  TT TT TT TT TT TT TT TT Sealed-at timestamp
      +0x5A  05 00                    Version length = 5
      +0x5C  30 2E 31 2E 30           "0.1.0"
      +0x61  00                       Has note = no
      +0x62  [4096 bytes plaintext]   Original file data
      ...    [padding bytes]          PADME random padding
```

---

## 18. Version History

| Version | Date       | Changes                  |
|---------|------------|--------------------------|
| 1.0     | 2026-03-07 | Initial format release   |
