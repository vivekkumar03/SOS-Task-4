# Security Findings and Remediations

**AES-256-GCM SOS Assignment Task 4 -Encryption Decryption | Format Version 1 | Review Summary: 29 October 2026**

## Executive Summary

The original program used suitable cryptographic algorithms but handled several critical security requirements incorrectly. The main risks were repeated GCM nonces, inexpensive password guessing, and printing plaintext without checking authentication. Later changes added strict parsing, safer file operations, a versioned authenticated header, and build hardening.

**Outcome:** The ten documented historical findings have been addressed in the reviewed code. Functional and selected sanitizer checks passed on macOS. This is a coursework assessment, not an independent audit or a production-security certification.

| Security goal | Current control |
| --- | --- |
| Keep messages confidential | AES-256-GCM with a derived 32-byte key |
| Detect changed data | GCM tag verified before plaintext output; header authenticated as AAD |
| Slow password guessing | PBKDF2-HMAC-SHA256 with 600,000 iterations; minimum password length for encryption |
| Reject hostile input | Bounded lengths, recognized metadata, canonical Base64, exact file framing |
| Protect local files and input | Overwrite confirmation, no-follow input, restrictive output permissions, terminal restoration |

For the beginner-level explanation and code walkthrough, see [GUIDE.md](GUIDE.md).

## Scope and CVE Status

This report covers the vulnerabilities identified in the original `vuln_lab` implementation and the fixes applied in this teaching copy. No CVE identifiers are assigned to these project-specific findings. A CWE identifies a weakness class; it is not a CVE identifier.

The implementation remains a coursework example and has not undergone an independent security audit. Do not rely on it for production data.

The review covers [crypto_common.c](vuln_lab/crypto_common.c), [crypto_common.h](vuln_lab/crypto_common.h), [task41enc.c](vuln_lab/task41enc.c), [task41dec.c](vuln_lab/task41dec.c), and [Makefile](vuln_lab/Makefile).

**Terminology:** CWE describes a weakness category. CVE identifies a particular publicly recorded vulnerability in a particular product. The CWE mappings here are review classifications, not official CVE assignments. A similar CWE does not mean this project is affected by another product's CVE.

## Findings at a Glance

| ID | Historical issue | CWE mapping | Current status |
| --- | --- | --- | --- |
| F01 | GCM tag-verification result ignored | CWE-354 | Fixed: output follows successful authentication |
| F02 | Constant salt and GCM nonce | CWE-323, CWE-760 | Fixed: fresh cryptographic randomness |
| F03 | One PBKDF2 iteration | CWE-916 | Fixed: 600,000 iterations for encryption |
| F04 | Header-length subtraction before validation | CWE-20, CWE-191, CWE-125 | Fixed: validate before pointer/length use |
| F05 | Unbounded ciphertext-file allocation | CWE-789, CWE-400 | Fixed: encoded and decoded size caps |
| F06 | Permissive Base64 and NUL/trailing-data handling | CWE-20 | Fixed: canonical decoding and exact framing |
| F07 | Silent message/password truncation | CWE-20 | Fixed: drain and reject invalid lines |
| F08 | Output path could follow a symlink | CWE-59 | Fixed: refuse symlinks and restrict file operations |
| F09 | Ordinary error paths bypassed secret cleanup | CWE-226, CWE-459 | Fixed for ordinary returns; signal-exit exception remains |
| F10 | Unchecked BIO memory-buffer result | CWE-252; potential CWE-476 consequence | Defensive gap closed; no exploit demonstrated |

## Related CWE/CVE Examples

The CVEs below are real examples from other products. They illustrate the CWE categories; they are not CVEs for this project and do not establish that this code has the same vulnerability.

| CWE | External NVD example | Relationship to this project |
| --- | --- | --- |
| CWE-120: Buffer Copy without Checking Size of Input | [CVE-2020-5133](https://nvd.nist.gov/vuln/detail/CVE-2020-5133): SonicOS buffer-overflow denial of service | Not identified here. Bounded input truncation is not evidence of an unchecked-copy overflow. |
| CWE-400: Uncontrolled Resource Consumption | [CVE-2023-21090](https://nvd.nist.gov/vuln/detail/CVE-2023-21090): Android permission-parser resource exhaustion | Analogous weakness class to F05; the lab's file-allocation issue is fixed. |
| CWE-476: NULL Pointer Dereference | [CVE-2022-40476](https://nvd.nist.gov/vuln/detail/CVE-2022-40476): Linux `io_uring` null-pointer dereference | Potential consequence of F10's earlier unchecked result, not a demonstrated failure here. |
| CWE-457: Use of Uninitialized Variable | [CVE-2026-11137](https://nvd.nist.gov/vuln/detail/CVE-2026-11137): Chrome ANGLE uninitialized use | Not identified here; included only as an external teaching example. |

## Historical Findings and Fixes

### 1. GCM Authentication Result Was Ignored (Fixed)

- **CWE:** CWE-354, Improper Validation of Integrity Check Value
- **CVE:** None assigned
- **Impact:** The decryptor ignored the return value from `EVP_DecryptFinal_ex`. A wrong password or modified ciphertext could therefore result in unauthenticated plaintext being printed as if decryption succeeded.
- **Fix applied:** Decryption now stops when tag verification fails, cleanses the allocated plaintext and key material, and reports an authentication error. Plaintext is only printed after successful verification.

### 2. GCM Nonce and KDF Salt Were Constant (Fixed)

- **CWE:** CWE-323, Reusing a Nonce, Key Pair in Encryption; CWE-760, Use of a One-Way Hash with a Predictable Salt
- **CVE:** None assigned
- **Impact:** Every encryption reused the same IV and salt. For the same password, this reused the AES-GCM key/nonce pair, which can compromise confidentiality and authentication. A fixed salt also made key derivation deterministic for a given password.
- **Fix applied:** The encryptor now obtains a fresh salt and IV from OpenSSL's cryptographic random generator and fails closed if random generation fails.

### 3. PBKDF2 Used an Insufficient Work Factor (Fixed)

- **CWE:** CWE-916, Use of Password Hash With Insufficient Computational Effort
- **CVE:** None assigned
- **Impact:** One PBKDF2 iteration made offline password guessing against captured ciphertext unnecessarily cheap.
- **Fix applied:** PBKDF2-HMAC-SHA256 now uses 600,000 iterations, increasing the cost of each password guess.

### 4. Malformed Ciphertext Lengths Could Cause Invalid Memory Access (Fixed)

- **CWE:** CWE-20, Improper Input Validation; CWE-191, Integer Underflow; CWE-125, Out-of-bounds Read
- **CVE:** None assigned
- **Impact:** The decoder did not verify that decoded data contained the complete salt, IV, and tag before creating component pointers and subtracting the header length. Short input could underflow the unsigned length calculation and lead to out-of-bounds reads or invalid allocation sizes.
- **Fix applied:** The decoder validates decoded length against the complete header and maximum ciphertext size before taking component pointers or converting the ciphertext length to `int`.

### 5. Unbounded Ciphertext File Allocation (Fixed)

- **CWE:** CWE-789, Memory Allocation with Excessive Size; CWE-400, Uncontrolled Resource Consumption
- **CVE:** None assigned
- **Impact:** The decryptor allocated memory based on the entire input file size before imposing a limit. An oversized file could exhaust process memory. The original code also narrowed file-derived lengths to `int` without first constraining them.
- **Fix applied:** The decoder checks the opened regular file's size with `fstat`, caps the encoded input before allocation, and bounds the decoded ciphertext. It checks for extra bytes after the measured content. These bounds also keep lengths passed to OpenSSL within the supported integer range.

### 6. Base64 and Embedded-NUL Input Was Not Strictly Validated (Fixed)

- **CWE:** CWE-20, Improper Input Validation
- **CVE:** None assigned
- **Impact:** The BIO-based decoder did not explicitly validate the complete Base64 alphabet, padding, or the raw file for embedded NUL bytes. NUL termination could cause parsing to stop before the end of the file, allowing trailing bytes to be ignored.
- **Fix applied:** The decoder validates Base64, decodes, then re-encodes and requires an exact match, rejecting nonzero unused padding bits. Only one optional LF or CRLF is allowed; other whitespace, appended records, and extra decoded bytes are rejected. The file reader rejects embedded NUL bytes, and the authenticated header records the exact ciphertext length.

### 7. Message and Password Inputs Could Be Silently Truncated (Fixed)

- **CWE:** CWE-20, Improper Input Validation
- **CVE:** None assigned
- **Impact:** The previous bounded input handling could silently accept only a prefix of an overlong line. Embedded NUL bytes in message input could also make string-length handling truncate the message.
- **Fix applied:** Message and password lines are read with explicit bounds. Overlong input and NUL-containing input are rejected rather than silently truncated; the password reader consumes the remainder of an overlong line and cleanses the rejected buffer.

### 8. Ciphertext Output Could Follow a Symlink (Fixed)

- **CWE:** CWE-59, Improper Link Resolution Before File Access
- **CVE:** None assigned
- **Impact:** Opening the fixed output path with `fopen(..., "w")` followed a pre-existing symlink. In a writable working directory, this could overwrite another file accessible to the process.
- **Fix applied:** The encryptor refuses symlink and non-regular output paths and requires `/dev/tty` confirmation before replacing an existing regular file. New output is published with an atomic no-clobber hard link. Confirmed replacements recheck the original device/inode before renaming. The decoder opens input with `O_NOFOLLOW` and checks that it is regular. Temporary ciphertext has mode `0600`.

### 9. Sensitive Buffers Were Not Cleansed on Every Error Path (Fixed)

- **CWE:** CWE-226, Sensitive Information in Resource Not Cleared Before Reuse; CWE-459, Incomplete Cleanup
- **CVE:** None assigned
- **Impact:** Calls to the immediate-exit error helper could bypass cleanup after passwords, derived keys, or plaintext had been placed in memory. Process termination releases its memory to the operating system, but uncleansed secrets can remain available to crash dumps or other process-memory inspection mechanisms.
- **Fix applied:** Encoder and decoder failures now converge on shared cleanup paths. They free allocated memory and OpenSSL contexts, close open files, remove unfinished temporary ciphertext, and cleanse password, key, and plaintext buffers before returning.

### 10. Base64 BIO Memory-Buffer Result Was Not Checked (Defensive Gap Closed)

- **CWE:** CWE-252, Unchecked Return Value; potential CWE-476, NULL Pointer Dereference
- **CVE:** None assigned
- **Impact:** The encoder dereferenced the output pointer from `BIO_get_mem_ptr` without checking whether the API call succeeded. This was a defensive robustness issue; no normal-operation failure was demonstrated.
- **Fix applied:** The encoder checks both the API return value and the resulting pointer, and reports failure to its caller. The encoder then uses its normal cleanup path.

## Additional Hardening Implemented

These are defense-in-depth controls and extensions to the earlier fixes, not six newly demonstrated exploits. CWE associations explain the risk each control addresses.

| Control | Implementation | Related CWE |
| --- | --- | --- |
| Password policy | New encryptions require 12 through 255 password bytes and matching confirmation; invalid entries can be retried | CWE-521: Weak Password Requirements |
| Authenticated metadata | Magic, version, KDF ID, iterations and length are authenticated with salt/IV as AAD | CWE-354: Improper Validation of Integrity Check Value |
| Bounded KDF cost | Reject iteration counts outside 600,000 through 2,000,000 before derivation | CWE-400: Uncontrolled Resource Consumption |
| Canonical encoding | Decode, re-encode, and compare; reject extra bytes and noncanonical padding | CWE-20: Improper Input Validation |
| Nonblank message policy | Reject empty or ASCII-whitespace-only plaintext before password input; preserve whitespace in valid messages | CWE-20: Improper Input Validation (application input policy, not a demonstrated cryptographic weakness) |
| File protection | Terminal confirmation, atomic no-clobber creation, `O_NOFOLLOW`, regular-file checks | CWE-59: Improper Link Resolution Before File Access |
| Secret input and terminal state | Unbuffered stdin; temporary restoration handlers while echo is disabled | CWE-226: Sensitive Information in Resource Not Cleared Before Reuse; CWE-459: Incomplete Cleanup |
| Hardened build | Stack protection, fortification, PIE, format warnings; Linux RELRO/binding/stack flags | Defense in depth, not proof that a particular CWE is eliminated |

**Policy limits:** Password length is measured in bytes, not Unicode characters or estimated entropy. Repeated and common passwords can still satisfy the minimum. Metadata is serialized explicitly in big-endian order; unsupported formats/KDFs and inconsistent lengths fail closed.

**Password retries:** Both programs permit three attempts per run. Encryption retries invalid input or confirmation mismatch without re-reading the message. Decryption retries invalid input and authentication failure, cleansing rejected passwords, keys and tentative plaintext and resetting GCM before each new attempt. The error deliberately does not distinguish an incorrect password from modified ciphertext. EOF and I/O/terminal failures stop immediately. Failed encryption attempts create no output; plaintext is never displayed before successful authentication. The limit resets when the process restarts and is not an account lockout or a defense against offline guessing.

**Signal behavior:** SIGINT, SIGTERM, SIGHUP, SIGQUIT and SIGTSTP restore terminal settings and terminate. SIGTSTP deliberately exits instead of suspending. SIGKILL and SIGSTOP cannot be caught. Signal termination calls `_exit`, so it does not run ordinary memory cleanup.

## Version-1 File Layout

Offsets refer to the decoded binary package. Base64 wraps the entire package.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | Magic: `T41E` |
| 4 | 1 | Format version: 1 |
| 5 | 1 | KDF ID: 1 = PBKDF2-HMAC-SHA256 |
| 6 | 4 | Iteration count, big-endian |
| 10 | 4 | Ciphertext length, big-endian (1 through 4,095 bytes) |
| 14 | 16 | Random salt |
| 30 | 12 | Random IV |
| 42 | 16 | GCM tag |
| 58 | Variable | Ciphertext |

The first 42 bytes are AAD. The file must contain exactly the length recorded in the header, plus the 58-byte overhead. The encoder writes one final LF; the decoder accepts no line ending, one LF, or one CRLF.

## Build and Cleanup Notes

`build.sh` invokes `make all` and does not require a clean build. Run it as `bash build.sh` unless the executable bit is set. `make clean` removes `text.ct` along with build artifacts, so preserve or back up generated ciphertext before using that target.

The Makefile uses `pkg-config` for `libcrypto` when available, Homebrew OpenSSL 3 as a macOS fallback, or system include/library paths otherwise. `CC`, `CFLAGS`, `CPPFLAGS`, `LDFLAGS`, `LDLIBS`, `OPENSSL_PREFIX`, and `HARDEN_*` variables can be overridden. The supported platform model is POSIX macOS/Linux, not native Windows.

## Verification

The detailed case inventory, expected outcomes, revision scope and verification limits are recorded in [TEST_CASES.md](TEST_CASES.md).

Recorded runs were performed on macOS using Apple Clang and Homebrew OpenSSL 3. Tests used temporary directories rather than replacing repository ciphertext. Earlier headerless-format tests and the later version-1 checks are distinguished below.

| Test group | Recorded outcome | Evidence scope |
| --- | --- | --- |
| Round trip and wrong password | Passed | Version 1 recovers the message; wrong password fails authentication |
| Header, salt, IV, tag and ciphertext tampering | Passed | Altered fields rejected; no decrypted-message output |
| Repeated encryption | Passed | Same message/password produced different encrypted files; not a statistical randomness test |
| Empty, short, truncated, malformed and oversized files | Passed | Input rejected before unsafe use |
| Canonical Base64 and exact framing | Passed | Nonzero unused pad bits, extra decoded bytes, NUL, extra LF and trailing spaces rejected |
| Password and message limits | Passed | Short encryption passwords, blank/ASCII-whitespace-only messages and overlong input rejected; maximum sizes accepted; valid leading/trailing whitespace preserved |
| Password retries and confirmation | Passed under ASan/UBSan | 16 cases: mismatch/input recovery, wrong-then-correct decryption, third-attempt success, exhaustion, EOF and tampered-tag rejection |
| KDF work-factor bounds | Passed | Out-of-policy counts rejected; changing an allowed count fails authentication |
| Overwrite and filesystem checks | Passed | Approval/denial, unattended refusal, symlink/FIFO rejection and `0600` permissions checked |
| Output races and cleanup | Passed | Newly appearing output and changed confirmed inode preserved; temporary output removed |
| Terminal restoration | Passed | Pseudo-terminal tests for all five handled signals |
| ASan and UBSan | No findings in exercised paths | Version-1 round trip, wrong password, 20 malformed/tampered file cases, weak/overlong/NUL input |
| OpenSSL CLI | Partial independent check | Earlier PBKDF2 known vector and GCM algorithm availability; not application-output interoperability |
| Hardened macOS build | Passed | Build and PIE executable flag checked |
| Linux portability | Dry run only | Recipe inspected; no Linux compilation or execution |

**Verification limits:** Leak detection was disabled because the macOS sanitizer runtime does not support it. The prebuilt OpenSSL library was not rebuilt with sanitizers. OpenSSL `enc` does not support AEAD/GCM, so independent CLI decryption of the application's ciphertext was not performed. Retry tests now demonstrate recovery after selected overlong/NUL-containing lines; they do not prove every possible input-stream behavior. Tests are not exhaustive fuzzing, allocation-failure injection, or an audit.

## Compatibility and Remaining Considerations

All previous headerless ciphertext formats are rejected, including the later random-salt/600,000-iteration format. Preserve old files and use the matching old decoder in an isolated environment to recover them before re-encrypting into version 1. There is no automatic legacy fallback or migration. The existing ciphertext in the worktree is not converted or overwritten by this update.

| Remaining consideration | Related CWE or scope | Practical limitation |
| --- | --- | --- |
| Offline password guessing | CWE-521 / CWE-916 risk area | Minimum length and PBKDF2 do not guarantee password strength |
| Confirmed-replacement race | CWE-367: Time-of-check Time-of-use Race Condition | Device/inode recheck and rename are separate operations; use a private directory |
| Parent-directory links | CWE-59 scope limit | `O_NOFOLLOW` protects only the final input component |
| Abrupt termination | CWE-459 / CWE-226 scope limit | Uncatchable signals cannot restore state; handled signal exits skip ordinary cleansing |
| Platform and audit coverage | Verification gap | Linux runtime, exhaustive fault handling and production suitability remain unverified |

**Conclusion:** The documented remediations improve the learning example substantially. They do not remove the need for strong passphrases, trusted directories, careful migration and independent review before any production use.
