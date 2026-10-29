# Makefile for task41enc and task41dec
#
# Uses the shared module crypto_common.o for code reuse.
# Requires: a C11 compiler and OpenSSL >= 3.0 development headers/libraries
#
# Targets:
#   make          – build both programs (default)
#   make clean    – remove object files, binaries, and text.ct

CC ?= cc
PKG_CONFIG ?= pkg-config
UNAME_S := $(shell uname -s)
OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcrypto 2>/dev/null)
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs libcrypto 2>/dev/null)

ifeq ($(strip $(OPENSSL_LIBS)),)
ifeq ($(UNAME_S),Darwin)
OPENSSL_PREFIX ?= $(shell command -v brew >/dev/null 2>&1 && brew --prefix openssl@3 2>/dev/null)
endif
ifneq ($(strip $(OPENSSL_PREFIX)),)
OPENSSL_CFLAGS = -I$(OPENSSL_PREFIX)/include
OPENSSL_LIBS = -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib -lcrypto
else
OPENSSL_LIBS = -lcrypto
endif
endif

CFLAGS ?= -O2
WARN_CFLAGS = -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security
HARDEN_CPPFLAGS ?= -D_FORTIFY_SOURCE=2
HARDEN_CFLAGS ?= -fstack-protector-strong -fPIE
ifeq ($(UNAME_S),Linux)
HARDEN_LDFLAGS ?= -pie -Wl,-z,relro,-z,now,-z,noexecstack
else ifeq ($(UNAME_S),Darwin)
HARDEN_LDFLAGS ?= -Wl,-pie
endif
CPPFLAGS += $(OPENSSL_CFLAGS) $(HARDEN_CPPFLAGS)
LDLIBS += $(OPENSSL_LIBS)

COMMON_SRC = crypto_common.c
COMMON_OBJ = crypto_common.o
COMMON_HDR = crypto_common.h

ENC_TARGET = task41enc
DEC_TARGET = task41dec

.PHONY: all clean
.DELETE_ON_ERROR:

# ── Default target ─────────────────────────────────────────────────────────
all: $(ENC_TARGET) $(DEC_TARGET)

# ── Shared object ──────────────────────────────────────────────────────────
$(COMMON_OBJ): $(COMMON_SRC) $(COMMON_HDR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARN_CFLAGS) $(HARDEN_CFLAGS) -std=c11 -c $< -o $@

# ── Encryption program ─────────────────────────────────────────────────────
$(ENC_TARGET): task41enc.c $(COMMON_OBJ) $(COMMON_HDR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARN_CFLAGS) $(HARDEN_CFLAGS) -std=c11 task41enc.c $(COMMON_OBJ) -o $@ $(LDFLAGS) $(HARDEN_LDFLAGS) $(LDLIBS)

# ── Decryption program ─────────────────────────────────────────────────────
$(DEC_TARGET): task41dec.c $(COMMON_OBJ) $(COMMON_HDR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARN_CFLAGS) $(HARDEN_CFLAGS) -std=c11 task41dec.c $(COMMON_OBJ) -o $@ $(LDFLAGS) $(HARDEN_LDFLAGS) $(LDLIBS)

# ── Cleanup ────────────────────────────────────────────────────────────────
clean:
	rm -f $(COMMON_OBJ) $(ENC_TARGET) $(DEC_TARGET) text.ct
