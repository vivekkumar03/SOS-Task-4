#**FINDINGS**

# Security Findings and Remediations

## Scope and CVE Status

This report covers the vulnerabilities identified in the original `vuln_lab` implementation and the fixes applied in this teaching copy. No CVE identifiers are assigned to these project-specific findings. A CWE identifies a weakness class; it is not a CVE identifier.

The implementation remains a coursework example and has not undergone an independent security audit. Do not rely on it for production data.

## Related CWE/CVE Examples

The CVEs below are real examples from other products. They illustrate the CWE categories; they are not CVEs for this project and do not establish that this code has the same vulnerability.

| Weakness | External CVE example | Relevance to this code |
| --- | --- | --- |
| **CWE-120: Buffer Copy without Checking Size of Input** | [CVE-2020-5133](https://nvd.nist.gov/vuln/detail/CVE-2020-5133), a SonicOS buffer-overflow denial of service | No unchecked buffer-copy overflow was identified in this example. Its `memcpy` calls copy fixed-size fields into a buffer sized from those same fields. The earlier bounded-line input could truncate long messages, but that is an input-validation issue, not evidence of CWE-120. |
| **CWE-400: Uncontrolled Resource Consumption** | [CVE-2023-21090](https://nvd.nist.gov/vuln/detail/CVE-2023-21090), Android resource exhaustion while parsing permission declarations | The earlier decoder allocated based on an unbounded ciphertext-file size. **Fixed:** the current decoder caps the encoded file size before allocation and validates decoded length. |
| **CWE-476: NULL Pointer Dereference** | [CVE-2022-40476](https://nvd.nist.gov/vuln/detail/CVE-2022-40476), a Linux kernel `io_uring` null-pointer dereference | The earlier Base64 encoder did not check the result of `BIO_get_mem_ptr` before dereferencing its output. This was a defensive error-handling gap, not a demonstrated normal-operation null-pointer failure. **Fixed:** the return value and pointer are now checked before use. The CVE is an external category example, not a finding against this code. |
| **CWE-457: Use of Uninitialized Variable** | [CVE-2026-11137](https://nvd.nist.gov/vuln/detail/CVE-2026-11137), an uninitialized-use information disclosure in Google Chrome's ANGLE component | No direct use of an uninitialized variable was identified in this project. The cited Chrome issue is unrelated to this code and is included only as an example of CWE-457. |

## Findings

### 1. GCM Authentication Result Was Ignored

- **CWE:** CWE-354, Improper Validation of Integrity Check Value
- **CVE:** None assigned
- **Impact:** The decryptor ignored the return value from `EVP_DecryptFinal_ex`. A wrong password or modified ciphertext could therefore result in unauthenticated plaintext being printed as if decryption succeeded.
- **Fix applied:** Decryption now stops when tag verification fails, cleanses the allocated plaintext and key material, and reports an authentication error. Plaintext is only printed after successful verification.

### 2. GCM Nonce and KDF Salt Were Fixed

- **CWE:** CWE-323, Reusing a Nonce, Key Pair in Encryption; CWE-760, Use of a One-Way Hash with a Predictable Salt
- **CVE:** None assigned
- **Impact:** Every encryption reused the same IV and salt. For the same password, this reused the AES-GCM key/nonce pair, which can compromise confidentiality and authentication. A fixed salt also made key derivation deterministic for a given password.
- **Fix applied:** The encryptor now obtains a fresh salt and IV from OpenSSL's cryptographic random generator and fails closed if random generation fails.

### 3. PBKDF2 Used an Insufficient Work Factor

- **CWE:** CWE-916, Use of Password Hash With Insufficient Computational Effort
- **CVE:** None assigned
- **Impact:** One PBKDF2 iteration made offline password guessing against captured ciphertext unnecessarily cheap.
- **Fix applied:** PBKDF2-HMAC-SHA256 now uses 600,000 iterations, increasing the cost of each password guess.

### 4. Malformed Ciphertext Lengths Could Cause Invalid Memory Access

- **CWE:** CWE-20, Improper Input Validation; CWE-191, Integer Underflow; CWE-125, Out-of-bounds Read
- **CVE:** None assigned
- **Impact:** The decoder did not verify that decoded data contained the complete salt, IV, and tag before creating component pointers and subtracting the header length. Short input could underflow the unsigned length calculation and lead to out-of-bounds reads or invalid allocation sizes.
- **Fix applied:** The decoder validates decoded length against the complete header and maximum ciphertext size before taking component pointers or converting the ciphertext length to `int`.

### 5. Unbounded Ciphertext File Allocation (Fixed)

- **CWE:** CWE-789, Memory Allocation with Excessive Size; CWE-400, Uncontrolled Resource Consumption
- **CVE:** None assigned
- **Impact:** The decryptor allocated memory based on the entire input file size before imposing a limit. An oversized file could exhaust process memory. The original code also narrowed file-derived lengths to `int` without first constraining them.
- **Fix applied:** File seeking and size determination are checked, the encoded input is capped before allocation, and decoded ciphertext is limited to the application maximum. These bounds also keep lengths passed to OpenSSL within the supported integer range.

### 6. Base64 and Embedded-NUL Input Was Not Strictly Validated

- **CWE:** CWE-20, Improper Input Validation
- **CVE:** None assigned
- **Impact:** The BIO-based decoder did not explicitly validate the complete Base64 alphabet, padding, or the raw file for embedded NUL bytes. NUL termination could cause parsing to stop before the end of the file, allowing trailing bytes to be ignored.
- **Fix applied:** The decoder now checks Base64 length, alphabet, and padding before decoding with `EVP_DecodeBlock`. The file reader rejects embedded NUL bytes, and decoded lengths are validated before use.

### 7. Message and Password Inputs Could Be Silently Truncated

- **CWE:** CWE-20, Improper Input Validation
- **CVE:** None assigned
- **Impact:** The previous bounded input handling could silently accept only a prefix of an overlong line. Embedded NUL bytes in message input could also make string-length handling truncate the message.
- **Fix applied:** Message and password lines are read with explicit bounds. Overlong input and NUL-containing input are rejected rather than silently truncated; the password reader consumes the remainder of an overlong line and cleanses the rejected buffer.

### 8. Ciphertext Output Could Follow a Symlink

- **CWE:** CWE-59, Improper Link Resolution Before File Access
- **CVE:** None assigned
- **Impact:** Opening the fixed output path with `fopen(..., "w")` followed a pre-existing symlink. In a writable working directory, this could overwrite another file accessible to the process.
- **Fix applied:** The encryptor writes to a uniquely created temporary file with mode `0600`, flushes it, then atomically renames it to the output path. The rename replaces a symlink itself rather than following it.

### 9. Sensitive Buffers Were Not Cleansed on Every Error Path (Fixed)

- **CWE:** CWE-226, Sensitive Information in Resource Not Cleared Before Reuse; CWE-459, Incomplete Cleanup
- **CVE:** None assigned
- **Impact:** Calls to the immediate-exit error helper could bypass cleanup after passwords, derived keys, or plaintext had been placed in memory. Process termination releases its memory to the operating system, but uncleansed secrets can remain available to crash dumps or other process-memory inspection mechanisms.
- **Fix applied:** Encoder and decoder failures now converge on shared cleanup paths. They free allocated memory and OpenSSL contexts, close open files, remove unfinished temporary ciphertext, and cleanse password, key, and plaintext buffers before returning.

### 10. Base64 BIO Memory-Buffer Result Was Not Checked (Fixed)

- **CWE:** CWE-476, NULL Pointer Dereference
- **CVE:** None assigned
- **Impact:** The encoder dereferenced the output pointer from `BIO_get_mem_ptr` without checking whether the API call succeeded. This was a defensive robustness issue; no normal-operation failure was demonstrated.
- **Fix applied:** The encoder checks both the API return value and the resulting pointer, and reports failure to its caller. The encoder then uses its normal cleanup path.

## Build and Cleanup Notes

`build.sh` invokes `make all` and does not require a clean build. Run it as `bash build.sh` unless the executable bit is set. `make clean` removes `text.ct` along with build artifacts, so preserve or back up generated ciphertext before using that target.

## Compatibility and Remaining Considerations

Ciphertexts created by the previous implementation are not compatible: they used a fixed salt/IV and one PBKDF2 iteration, while this version uses random values and 600,000 iterations. The current file format does not store a version or KDF parameters, so future algorithm or parameter changes will require an explicit format migration. Strong passphrases are still important because offline guessing remains possible against any password-based encryption format.



