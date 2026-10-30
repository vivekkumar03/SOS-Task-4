# SOS Assignment Task 4 -Encryption Decryption

This is a portable C source handoff for macOS and Linux. Each system must compile its own binaries; do not distribute a binary built on a different operating system. This coursework example has not undergone an independent security audit and is not for production data.

## Prerequisites

Install a C11 compiler, `make`, `pkg-config`, and OpenSSL 3 development files.

On macOS with Homebrew:

```sh
xcode-select --install
brew install openssl@3 pkg-config
```

On Debian/Ubuntu Linux:

```sh
sudo apt update
sudo apt install build-essential pkg-config libssl-dev
```

The OpenSSL development package should provide OpenSSL 3. If a Linux distribution supplies an older OpenSSL version, use its OpenSSL 3 development package or a supported distribution release.

## Build and Run

```sh
cd vuln_lab
./build.sh
./task41enc
./task41dec
```

The Makefile uses `pkg-config` when available, Homebrew OpenSSL 3 as a macOS fallback, and system paths otherwise. `build.sh` changes to its own directory, so it can also be run by path from another working directory. Running `make clean` deletes `text.ct` as well as the binaries and object file; back up ciphertext before using it.

New encryption requires a password of 12 to 255 bytes and asks for confirmation. Password entry can be retried up to three times. Existing output requires confirmation in an interactive terminal; symlinks are refused. The version-1 authenticated file format is incompatible with prior headerless ciphertext.

## Handoff Contents

Share the source and documentation, not locally built artifacts. Include:

- `vuln_lab/` C sources, header, `Makefile`, and executable `build.sh`
- `README.md`, `GUIDE.md`, `SECURITY.md`, and `TEST_CASES.md`

Do not include `task41enc`, `task41dec`, `crypto_common.o`, `build.log`, `.DS_Store`, or `text.ct`. Those are local build outputs, metadata, logs, or generated ciphertext. The recipient should build locally with the instructions above.

## Documentation

- [GUIDE.md](GUIDE.md): beginner explanation and source walkthrough.
- [SECURITY.md](SECURITY.md): CWE mappings, remediations, security limits, and verification summary.
- [TEST_CASES.md](TEST_CASES.md): test-case inventory and recorded outcomes.
