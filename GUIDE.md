# Beginner's Guide to the Encryption Example

This guide explains the example for readers who are new to encryption. It describes what each cryptographic part does, how the C programs fit together, and what happens to a message from input to output.

This is a learning example, not a security product. It has not had an independent security audit.

## The Basic Idea

Encryption turns readable information, called **plaintext**, into unreadable-looking information, called **ciphertext**. A **password** is used to make a cryptographic key. The key encrypts and later decrypts the message.

This program uses AES-256-GCM. AES is the encryption algorithm; `256` means its key is 256 bits (32 bytes); GCM is a mode that also checks that the ciphertext was not changed. The check value is called an **authentication tag**. If the tag does not verify, the program must not show the decrypted text.

The password is not used directly as the AES key. PBKDF2, a password-based key derivation function, repeatedly processes the password with a random **salt** to make the key. The salt is stored with the encrypted message; it is not a secret. The repeated work makes guessing passwords from a stolen ciphertext slower.

AES-GCM also needs a unique **IV** (initialization vector, also called a nonce) for each encryption with a given key. The IV is stored with the ciphertext and does not need to be secret. Reusing an IV with the same key can seriously weaken GCM, so this program generates a new random IV for each encryption.

**Base64 is not encryption.** It converts binary bytes into printable characters so the encrypted data can be written as text in `text.ct`.

## Data Flow

```mermaid
flowchart LR
    M[Message] --> E[Encryptor]
    P[Password] --> K[PBKDF2 key derivation]
    S[Random salt] --> K
    K --> AES[AES-256-GCM]
    IV[Random IV] --> AES
    E --> AES
    AES --> C[Ciphertext and authentication tag]
    S --> PACK[Package salt, IV, tag, ciphertext]
    IV --> PACK
    C --> PACK
    PACK --> B[Base64 text]
    B --> F[text.ct]
    F --> D[Decryptor]
    P --> KD[PBKDF2 key derivation]
    S --> KD
    D --> KD
    KD --> DEC[AES-GCM decrypt and verify tag]
    IV --> DEC
    C --> DEC
    DEC --> OUT[Print plaintext only after verification]
```

The binary data stored before Base64 encoding has this layout:

| Part | Size | Purpose |
| --- | ---: | --- |
| Salt | 16 bytes | Recreates the same derived key during decryption |
| IV | 12 bytes | Recreates the GCM operation; generated randomly for each encryption |
| GCM tag | 16 bytes | Lets the decryptor detect the wrong password or changed data |
| Ciphertext | Same size as the message | The encrypted message bytes |

The salt, IV, tag, and ciphertext are all stored together. None of these fields is a substitute for the password: keep the password private and choose a strong one.

## Important Terms

- **Key:** The secret bytes that the encryption algorithm uses. Here the key is derived from the password and is 32 bytes long.
- **Salt:** Random data mixed into password-based key derivation. It makes the derived key different between encryptions, even when the password is the same. It can be public.
- **IV / nonce:** Per-encryption input to AES-GCM. It can be public, but must not be reused with the same key.
- **Authentication tag:** A value created by GCM and checked during decryption. It detects a wrong password or modified ciphertext.
- **KDF:** A key derivation function. PBKDF2 makes a fixed-size key from a password and salt by repeating a hash operation many times.
- **Buffer:** A region of memory holding bytes or text while the program works on it.
- **OpenSSL EVP:** OpenSSL's high-level interface for cryptographic operations. The programs use it rather than implementing AES themselves.

## Files at a Glance

### `crypto_common.h`

This header is shared by both programs. It includes OpenSSL and standard C declarations, sets the parameters and size limits, defines the function-pointer type for key derivation, and declares shared helper functions.

Key settings include:

- `SALT_LEN`, `IV_LEN`, `KEY_LEN`, and `TAG_LEN`: the sizes of the cryptographic fields.
- `PBKDF2_ITER`: 600,000 PBKDF2 iterations.
- `MAX_MSG_LEN`: storage allocated for a message including its terminating NUL byte. Because one byte is reserved for that terminator, the current input loop accepts at most 4,095 message bytes.
- `MAX_PASS_LEN`: password buffer size including its terminating NUL byte. The largest accepted password is 255 bytes.
- `OUTPUT_FILE`: the ciphertext filename, `text.ct`.
- `HEADER_LEN` and `MAX_B64_LEN`: derived sizes used by the decoder to validate file contents before using them.

The header also defines `kdf_fn_t`, a C function-pointer type describing the arguments and result expected from a key-derivation function. The programs assign `derive_key` to this type before calling it; this leaves room to swap the KDF implementation without changing the call pattern.

### `crypto_common.c`

This file implements helpers used by the encoder and decoder:

- `derive_key()` calls OpenSSL's `PKCS5_PBKDF2_HMAC()` with SHA-256, the configured iteration count, the salt, and a 32-byte output key.
- `base64_encode()` writes binary input through an OpenSSL Base64 BIO and returns a heap-allocated printable string. It checks BIO operations and the memory-buffer result. On failure it frees the BIO chain and returns `NULL` so the caller can clean up.
- `base64_decode()` checks the Base64 length, alphabet, and padding, then decodes with `EVP_DecodeBlock()`. It adjusts the output length for Base64 padding. Invalid data or allocation failure returns `NULL`.
- `read_password()` disables terminal echo when input comes from an interactive terminal. It reads through the end of the line, rejects overlong or NUL-containing input rather than accepting a prefix, restores terminal settings, and clears a rejected password buffer. When input is redirected or piped, terminal echo is not applicable.
- `crypto_error()` is a simple print-and-exit helper retained in the shared module. The encoder and decoder use their own cleanup paths instead, so errors after sensitive data is read do not bypass cleanup.

### `task41enc.c`: Encryption

The encoder performs these steps:

1. **Read the message.** It reads through the newline, rejects empty messages, messages over the limit, and embedded NUL bytes. A C string ends at a NUL byte, so accepting one could make the program handle only part of the input.
2. **Read the password.** `read_password()` hides typed characters in a terminal and rejects an empty or invalid password.
3. **Create salt and IV.** OpenSSL's `RAND_bytes()` supplies fresh random bytes. If the random generator fails, encryption stops.
4. **Derive the key.** `derive_key()` uses the password and salt to produce the AES key. The salt is saved with the output so decryption can derive the same key.
5. **Encrypt with AES-GCM.** `EVP_EncryptInit_ex()` selects AES-256-GCM, the context is configured with the IV length, and the key and IV are supplied. `EVP_EncryptUpdate()` encrypts the message. `EVP_EncryptFinal_ex()` completes the operation, and `EVP_CTRL_GCM_GET_TAG` retrieves the authentication tag.
6. **Package and encode the result.** The program concatenates salt, IV, tag, and ciphertext, then Base64-encodes that binary package.
7. **Write safely.** It creates a temporary file with restrictive permissions, writes and flushes the Base64 text, then renames the temporary file to `text.ct`. The rename avoids following a pre-existing symlink at the output path. Failed writes remove the temporary file.
8. **Clean up.** One cleanup section frees allocated memory and the OpenSSL context, closes open file handles, removes an unfinished temporary file, and clears password, key, message, tag, and package buffers before returning.

The `EVP_CIPHER_CTX` is an OpenSSL object that holds the state of an encryption operation. The `EVP_*` functions are OpenSSL's calls for setting up, running, and finishing that operation. Most return a success value; the code checks those values and takes the cleanup path on failure.

### `task41dec.c`: Decryption

The decoder reverses the process, with an important verification step:

1. **Read and bound the file.** It checks seeking and file size before allocating memory. The size limit prevents an attacker or accidental huge file from causing an unbounded allocation.
2. **Validate and decode Base64.** It rejects embedded NUL bytes, removes trailing newline characters, and calls `base64_decode()`.
3. **Check the package size.** It requires all header fields and a nonempty ciphertext, and rejects decoded data larger than the configured message limit before forming pointers into the buffer.
4. **Recover fields.** Pointers identify the salt, IV, tag, and ciphertext inside the decoded package. These pointers refer to existing memory; the program does not allocate separate copies for each field.
5. **Derive the key.** The password and stored salt are passed through the same PBKDF2 settings used by encryption.
6. **Decrypt and verify.** `EVP_DecryptUpdate()` produces plaintext bytes in memory. These bytes are not printed yet. `EVP_DecryptFinal_ex()` checks the GCM tag. A wrong password or altered data fails this check.
7. **Print only verified plaintext.** The program adds a NUL terminator and prints the message only after tag verification succeeds.
8. **Clean up every way out.** Both success and error paths converge on one cleanup section that closes files, frees the OpenSSL context and buffers, and cleanses the password, key, and plaintext.

The authentication tag is essential: decryption can produce bytes even when the password is wrong or the ciphertext was changed. The result must be treated as untrusted until GCM verification succeeds.

### `Makefile` and `build.sh`

The Makefile compiles `crypto_common.c` once into `crypto_common.o`, then links that shared object into `task41enc` and `task41dec`. It obtains the OpenSSL 3 installation prefix from Homebrew and passes the include and library paths to the compiler.

Run the build helper from this directory:

```sh
./build.sh
```

The script calls `make all`; it does not clean first. `make clean` removes the object file, both programs, and `text.ct`, so do not use that target if you need to keep the generated ciphertext.

## Try It

```sh
./build.sh
./task41enc
./task41dec
```

Enter a nonempty message and password when prompted. The encoder writes `text.ct` in the current working directory. The decoder reads that file and prompts for the same password. Altering the file or entering a different password should produce an authentication error instead of printing plaintext.

## Security and Compatibility Notes

- A longer, hard-to-guess password is important. PBKDF2 slows guesses; it cannot make a weak password strong.
- Salt, IV, ciphertext, and tag are stored together and are not secret. Do not store the password alongside `text.ct`.
- Ciphertext written by the earlier lab version is incompatible with this version because the salt, IV, and PBKDF2 settings changed.
- The file format currently has no version field or stored KDF parameters, so future parameter changes need an explicit format migration.
- This example prints decrypted data to the terminal and does not provide a production key-management system, backup policy, or independent security review.