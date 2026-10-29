# Test Cases and Recorded Results

**AES-256-GCM SOS Assignment Task 4 -Encryption Decryption | Format Version 1 | Updated: 29 October 2026**

## Purpose

This document records the test cases exercised during development. It is a test report, not an executable test runner. Creating this report did not rerun the tests. Results refer to the implementation revision present when each group was run; the full matrix was not rerun after every later change.

See [GUIDE.md](GUIDE.md) for the code walkthrough and [SECURITY.md](SECURITY.md) for findings, CWE mappings and remaining risks.

## Environment and Method

| Item | Recorded environment or method |
| --- | --- |
| Platform | macOS on Apple Silicon |
| Compiler | Apple Clang, including `/usr/bin/gcc` as the Apple compiler driver |
| Cryptographic library | Homebrew OpenSSL 3 |
| Programs | [task41enc.c](vuln_lab/task41enc.c) and [task41dec.c](vuln_lab/task41dec.c) |
| Isolation | Temporary directories and generated fixtures; repository ciphertext was not replaced by the tests |
| Functional checks | Exit code, error text, prompt count, file existence/content and plaintext output |
| Interactive checks | Pseudo-terminals for overwrite confirmation and terminal-state restoration |
| Instrumented checks | Separate binaries with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) |

**Result key:** **Passed** means the expected behavior was observed in the recorded run. **No findings** applies only to the sanitizer paths exercised. **Partial** and **Dry run** identify checks that did not establish full runtime behavior.

## 1. Encryption and Authentication

| ID | Test case | Expected behavior | Recorded result |
| --- | --- | --- | --- |
| CR-01 | Encrypt and decrypt a message with the correct password | Recover the original message exactly | Passed |
| CR-02 | Decrypt with the wrong password | Authentication fails; no decrypted message displayed | Passed |
| CR-03 | Encrypt the same message/password twice into separate outputs | Encrypted file contents differ | Passed; not a statistical randomness assessment |
| CR-04 | Change a decoded ciphertext byte and re-encode | Authentication fails; no decrypted message displayed | Passed |
| CR-05 | Change a decoded GCM tag byte and re-encode | Authentication fails; no decrypted message displayed | Passed |
| CR-06 | Change a salt byte | Reject the file without plaintext output | Passed |
| CR-07 | Change an IV byte | Reject the file without plaintext output | Passed |

**Related CWEs:** CWE-354 (integrity validation), CWE-323 (nonce reuse), CWE-760 (predictable salt), CWE-916 (insufficient password-derivation effort). CR-03 supports varied-output behavior; it does not prove nonce uniqueness for all runs.

## 2. Versioned Header and KDF Policy

| ID | Test case | Expected behavior | Recorded result |
| --- | --- | --- | --- |
| HD-01 | Inspect a newly encrypted binary package | Magic `T41E`, version 1, KDF ID 1, 600,000 iterations and exact ciphertext length | Passed |
| HD-02 | Inspect numeric metadata fields | Iteration count and ciphertext length use big-endian byte order | Passed |
| HD-03 | Alter the magic | Reject the header | Passed |
| HD-04 | Alter the version | Reject the unsupported format | Passed |
| HD-05 | Alter the KDF ID | Reject the unsupported KDF | Passed |
| HD-06 | Set iterations to 1 | Reject below-policy work factor before derivation | Passed |
| HD-07 | Set iterations to 2,000,001 or 4,294,967,295 | Reject excessive work factor before derivation | Passed |
| HD-08 | Change iterations to the allowed value 600,001 without recomputing the tag | Authentication fails | Passed |
| HD-09 | Remove a ciphertext byte while keeping the header unchanged | Reject length mismatch | Passed |
| HD-10 | Append a decoded byte while keeping the header unchanged | Reject extra decoded data | Passed |

**Related CWEs:** CWE-20 (input validation), CWE-191 (integer underflow), CWE-125 (out-of-bounds read), CWE-400 (resource consumption), CWE-354 (integrity validation).

HD-08 changes the derived key as well as authenticated metadata. It is not, by itself, an independent AAD-only known-answer test. The code explicitly submits the first 42 header bytes as AAD in both programs.

## 3. File Framing and Base64

| ID | Test case | Expected behavior | Recorded result |
| --- | --- | --- | --- |
| IN-01 | Empty ciphertext file | Reject before password processing | Passed |
| IN-02 | Very short decoded package, such as Base64 `AAAA` | Reject incomplete header/package | Passed |
| IN-03 | Invalid Base64 characters, such as `!!!!` | Reject decoding | Passed |
| IN-04 | Embedded NUL byte in encoded input | Reject rather than parse only a prefix | Passed |
| IN-05 | Nonzero unused Base64 padding bits that decode to the same bytes | Reject the noncanonical representation | Passed |
| IN-06 | Append an extra LF after the permitted ending | Reject extra trailing whitespace | Passed |
| IN-07 | Append a space | Reject trailing data | Passed |
| IN-08 | Valid package with no final newline | Accept and decrypt correctly | Passed |
| IN-09 | Valid package with one final LF | Accept and decrypt correctly | Passed |
| IN-10 | Valid package with one final CRLF | Accept and decrypt correctly | Passed |
| IN-11 | 100,000-byte encoded input | Reject as oversized before file-buffer allocation | Passed |

**Related CWEs:** CWE-20, CWE-789 (excessive allocation), CWE-400. These are selected examples, not exhaustive parser fuzzing.

## 4. Message Input

These eight focused message cases were run after the whitespace-only policy was added, using the normal hardened build.

| ID | Message bytes before the newline | Expected behavior | Recorded result |
| --- | --- | --- | --- |
| MS-01 | Empty | Reject; no password prompt or output file | Passed |
| MS-02 | One ASCII space | Reject; no password prompt or output file | Passed |
| MS-03 | 4,095 ASCII spaces | Reject; no password prompt or output file | Passed |
| MS-04 | One tab | Reject; no password prompt or output file | Passed |
| MS-05 | Space, tab, CR, vertical tab, form feed, space | Reject as whitespace-only | Passed |
| MS-06 | `  hello world  ` | Preserve leading/trailing spaces through the round trip | Passed |
| MS-07 | Tab, space, `hello`, space, tab | Preserve surrounding whitespace exactly | Passed |
| MS-08 | `0` | Accept as nonblank content and recover exactly | Passed |

Earlier boundary checks also passed:

| ID | Test case | Expected behavior | Recorded result |
| --- | --- | --- | --- |
| MS-09 | 4,096 message bytes | Reject as overlong | Passed |
| MS-10 | 4,095 non-whitespace message bytes and a 255-byte password | Accept the maximum supported input sizes | Passed before confirmation was introduced |
| MS-11 | Embedded NUL in message input | Reject instead of silently truncating | Passed |

**Related CWE:** CWE-20. Rejecting blank messages is an application policy, not evidence that encrypting whitespace is cryptographically unsafe. Unicode whitespace handling was not tested; the current check uses the C character-classification function on individual bytes.

## 5. Password Retries and Confirmation

All 16 cases below passed using separate ASan/UBSan binaries after the retry update. The later whitespace-only-message change was tested separately.

### Encryption

| ID | Input sequence after a valid message | Expected behavior | Recorded result |
| --- | --- | --- | --- |
| PW-01 | Valid password, mismatched confirmation, then matching pair | Retry password input; encrypt without re-entering the message | Passed |
| PW-02 | 256-byte password line, then valid matching pair | Drain invalid line and recover at the next password prompt | Passed |
| PW-03 | Empty password, then valid matching pair | Retry and encrypt successfully | Passed |
| PW-04 | NUL-containing password line, then valid matching pair | Reject/drain invalid input and recover | Passed |
| PW-05 | Three short passwords followed by a valid pair | Stop after three attempts; create no output | Passed |
| PW-06 | Three confirmation mismatches | Stop after three attempts; create no output | Passed |
| PW-07 | EOF before password input | Exit promptly; create no output | Passed |
| PW-08 | Valid password, then EOF before confirmation | Exit promptly; create no output | Passed |

### Decryption

| ID | Input sequence for an existing valid encrypted file | Expected behavior | Recorded result |
| --- | --- | --- | --- |
| PW-09 | Wrong password, then correct password | Decrypt in the same process on attempt two | Passed |
| PW-10 | Two wrong passwords, then correct password | Decrypt on attempt three | Passed |
| PW-11 | 256-byte password line, then correct password | Drain invalid line and recover | Passed |
| PW-12 | Empty password, then correct password | Retry and decrypt | Passed |
| PW-13 | Three wrong passwords followed by the correct one | Stop at three; ignore the fourth; display no plaintext | Passed |
| PW-14 | Wrong password, then EOF | Exit promptly without plaintext | Passed |
| PW-15 | EOF without any password | Exit promptly without plaintext | Passed |
| PW-16 | Tampered tag and three correct-password entries | All attempts fail; never display plaintext | Passed |

**Related CWEs:** CWE-20, CWE-521 (weak password requirements), CWE-354, CWE-226 (sensitive resource clearing), CWE-459 (incomplete cleanup). The three-attempt limit is per process; it is not an account lockout and does not prevent offline guesses. Authentication failure cannot distinguish a wrong password from modified ciphertext.

## 6. Filesystem and Output Protection

| ID | Test case | Expected behavior | Recorded result |
| --- | --- | --- | --- |
| FS-01 | Existing regular output, no controlling terminal | Refuse replacement; preserve existing bytes | Passed |
| FS-02 | Existing regular output; answer `n` on terminal | Refuse replacement; preserve existing bytes | Passed |
| FS-03 | Existing regular output; answer `y` on terminal | Replace output and successfully decrypt the replacement | Passed before password confirmation was introduced |
| FS-04 | Input path is a symlink | Refuse input | Passed |
| FS-05 | Output path is a symlink | Refuse encryption; preserve link target | Passed |
| FS-06 | Input path is a FIFO | Reject without waiting for pipe input | Passed |
| FS-07 | Inspect newly published output permissions | Owner read/write only: `0600` | Passed |
| FS-08 | Another output appears while encryption is in progress | No-clobber publication fails; preserve arriving file; remove temporary output | Passed before password confirmation was introduced |
| FS-09 | Confirmed output inode changes before publication | Refuse replacement; preserve new file; remove temporary output | Passed before password confirmation was introduced |

**Related CWEs:** CWE-59 (link resolution), CWE-367 (TOCTOU race), CWE-459. The selected race tests passed, but the check followed by confirmed rename is still not an atomic conditional replacement. Use a private working directory.

Historical check: before overwrite confirmation was implemented, a forced failed output rename was tested and temporary output removal passed. That older scenario is not a current end-to-end overwrite-confirmation test.

## 7. Terminal Restoration

Pseudo-terminal tests verified that echo was disabled at the password prompt and the terminal settings were restored after each handled signal.

| ID | Signal | Expected behavior | Recorded result |
| --- | --- | --- | --- |
| TT-01 | SIGINT | Restore terminal state and terminate | Passed |
| TT-02 | SIGTERM | Restore terminal state and terminate | Passed |
| TT-03 | SIGHUP | Restore terminal state and terminate | Passed |
| TT-04 | SIGQUIT | Restore terminal state and terminate | Passed |
| TT-05 | SIGTSTP | Restore terminal state and terminate rather than suspend | Passed |

These tests preceded the retry/confirmation update and were not repeated at each retry prompt. SIGKILL and SIGSTOP cannot be caught. Signal exit does not execute ordinary secret-buffer cleanup. **Related CWE:** CWE-459.

## 8. Sanitizers and Independent Checks

| ID | Check | Recorded result | Limit |
| --- | --- | --- | --- |
| VF-01 | ASan/UBSan version-1 round trip and wrong-password path | No findings | Selected exercised paths only |
| VF-02 | ASan/UBSan 20 malformed/tampered file cases | No findings | Includes encoding/framing failures, modified fields and KDF policy values |
| VF-03 | ASan/UBSan weak, overlong and NUL-containing input | No findings | Selected message/password inputs |
| VF-04 | ASan/UBSan 16 retry/confirmation cases | No findings | Listed individually as PW-01 through PW-16 |
| VF-05 | OpenSSL CLI PBKDF2-HMAC-SHA256 known vector | Passed | Standard vector, not a comparison of the application's stored key |
| VF-06 | OpenSSL CLI AES-256-GCM algorithm listing | Passed | Algorithm availability, not application interoperability |
| VF-07 | OpenSSL `enc` decrypting application GCM output | Not performed: CLI does not support AEAD/GCM | No independent CLI GCM-decryption result |
| VF-08 | Hardened macOS compilation and executable inspection | Passed; PIE flag present | Does not demonstrate every mitigation's runtime behavior |
| VF-09 | Linux Makefile recipe | Dry run passed | No Linux compilation or execution |
| VF-10 | Alternate OpenSSL-discovery/override recipes | Dry-run inspection passed | Branch selection, not full builds on every environment |

Instrumented builds used `-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g` with `ASAN_OPTIONS=detect_leaks=0:halt_on_error=1` and `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. Leak detection was disabled because the installed macOS runtime reports it unsupported. The prebuilt OpenSSL library was not rebuilt with sanitizers.

## Interpretation and Remaining Coverage

- Recorded checks support the described behavior; they do not prove the absence of all vulnerabilities.
- No exhaustive fuzzing, allocation-failure injection, or independent security audit was performed.
- Not every header boundary, Unicode input, signal timing or concurrent filesystem modification was exercised.
- No full Linux runtime test or native Windows support was established.
- Historical tests used the prompts and format available at that revision. Reproduction on the current version must include password confirmation and account for the three-attempt limit.
- This document records prior executions. It does not provide persisted test scripts or logs, and no new test run was performed to create it.