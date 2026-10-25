# Makefile for task41enc and task41dec
#
# Uses the shared module crypto_common.o for code reuse.
# Requires: gcc, libssl-dev (OpenSSL >= 3.0)
#
# Targets:
#   make          – build both programs (default)
#   make clean    – remove object files, binaries, and text.ct

CC       = gcc
CFLAGS   = -Wall -Wextra -Wpedantic -O2 -std=c11
LDFLAGS  = -lssl -lcrypto

COMMON_SRC = crypto_common.c
COMMON_OBJ = crypto_common.o
COMMON_HDR = crypto_common.h

ENC_TARGET = task41enc
DEC_TARGET = task41dec

.PHONY: all clean

# ── Default target ─────────────────────────────────────────────────────────
all: $(ENC_TARGET) $(DEC_TARGET)

# ── Shared object ──────────────────────────────────────────────────────────
$(COMMON_OBJ): $(COMMON_SRC) $(COMMON_HDR)
	$(CC) $(CFLAGS) -c $< -o $@

# ── Encryption program ─────────────────────────────────────────────────────
$(ENC_TARGET): task41enc.c $(COMMON_OBJ) $(COMMON_HDR)
	$(CC) $(CFLAGS) task41enc.c $(COMMON_OBJ) -o $@ $(LDFLAGS)

# ── Decryption program ─────────────────────────────────────────────────────
$(DEC_TARGET): task41dec.c $(COMMON_OBJ) $(COMMON_HDR)
	$(CC) $(CFLAGS) task41dec.c $(COMMON_OBJ) -o $@ $(LDFLAGS)

# ── Cleanup ────────────────────────────────────────────────────────────────
clean:
	rm -f $(COMMON_OBJ) $(ENC_TARGET) $(DEC_TARGET) text.ct
