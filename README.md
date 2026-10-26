# AES-256-GCM Teaching Utility

This directory contains a small password-based encryption/decryption example. It is intended for coursework, not production use; it has not undergone a security audit. Build with:

For a beginner-friendly explanation of the cryptography and each source file, see [GUIDE.md](GUIDE.md).

```sh
make all
```

`make clean` removes the generated ciphertext file `text.ct` in addition to build outputs.

## Checks
1. Run an encrypt/decrypt round trip.
2. Modify `text.ct` and verify that decryption rejects the altered data.
3. Try short and malformed Base64 inputs under AddressSanitizer.
4. Encrypt the same message more than once and verify that the output differs.

Example instrumented build (GCC/Clang):

```sh
make clean
make CFLAGS='-Wall -Wextra -Wpedantic -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -std=c11' LDFLAGS='-lssl -lcrypto -fsanitize=address,undefined'
```

The implementation is still a teaching example and should not be used to protect production data.
