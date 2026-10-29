# AES-256-GCM Teaching Utility

This directory contains a small password-based encryption/decryption example. It is intended for coursework, not production use; it has not undergone a security audit. Build with:

For a beginner-friendly explanation of the cryptography and each source file, see [GUIDE.md](GUIDE.md).

```sh
make -C vuln_lab all
```

New passwords must be at least 12 bytes. Existing output requires confirmation on a terminal; symlinks are refused. The new authenticated version-1 format is not compatible with older headerless ciphertext. See [SECURITY.md](SECURITY.md) for the format and limits.

`make -C vuln_lab clean` removes the generated ciphertext file `text.ct` in addition to build outputs.

## Checks
1. Run an encrypt/decrypt round trip.
2. Modify `text.ct` and verify that decryption rejects the altered data.
3. Try short and malformed Base64 inputs under AddressSanitizer.
4. Encrypt the same message more than once and verify that the output differs.

Example instrumented build (GCC/Clang):

```sh
make -C vuln_lab -B CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined'
```

The implementation is still a teaching example and should not be used to protect production data.
