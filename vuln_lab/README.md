# Intentionally vulnerable teaching lab — DO NOT USE FOR REAL DATA

This directory is a separate teaching copy. The original files in the parent directory are the reference implementation. Build only in an isolated lab environment:

```sh
make clean all
```

## Student tasks
1. Compare this version with the parent directory's reference sources.
2. Run a normal encrypt/decrypt round trip.
3. Flip a character in `text.ct` and observe whether the decoder rejects tampering.
4. Try a short/malformed Base64 input under AddressSanitizer.
5. Review the key-derivation cost and repeated-encryption behavior.

Example instrumented build (GCC/Clang):

```sh
make clean
make CFLAGS='-Wall -Wextra -Wpedantic -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -std=c11' LDFLAGS='-lssl -lcrypto -fsanitize=address,undefined'
```

These faults are intentionally included for controlled education. Never use this directory with confidential data or deploy its binaries.
