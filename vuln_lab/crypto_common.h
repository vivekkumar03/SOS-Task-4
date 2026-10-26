/*
 * crypto_common.h
 *
 * Shared declarations for task41enc and task41dec.
 * Provides constants, type aliases, and function prototypes for:
 *   - PBKDF2-HMAC-SHA256 key derivation
 *   - Base64 encode/decode (via OpenSSL BIO)
 *   - Secure password reading (no echo)
 *   - Error handling
 *
 * Crypto algorithms used:
 *   Key derivation : PBKDF2-HMAC-SHA256  (RFC 2898 / PKCS#5)
 *   Cipher         : AES-256-GCM         (NIST SP 800-38D)
 *
 * File layout written to text.ct (binary before base64):
 *   [SALT_LEN bytes salt][IV_LEN bytes IV][TAG_LEN bytes GCM tag][ciphertext]
 */

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

/* ── Cryptographic parameters ─────────────────────────────────────────────── */
#define SALT_LEN       16          /* bytes – NIST recommends >= 16            */
#define IV_LEN         12          /* bytes – recommended GCM IV length        */
#define KEY_LEN        32          /* bytes – AES-256                          */
#define TAG_LEN        16          /* bytes – GCM authentication tag           */
#define PBKDF2_ITER    600000      /* PBKDF2-HMAC-SHA256 work factor            */

/* ── Application limits ───────────────────────────────────────────────────── */
#define MAX_MSG_LEN    4096
#define MAX_PASS_LEN   256
#define OUTPUT_FILE    "text.ct"
#define HEADER_LEN     (SALT_LEN + IV_LEN + TAG_LEN)
#define MAX_B64_LEN    (4 * ((HEADER_LEN + MAX_MSG_LEN + 2) / 3))

/* ── Function-pointer type for the key-derivation strategy ───────────────── */
/* Signature: (password, pass_len, salt, salt_len, out_key, key_len) -> 1 ok  */
typedef int (*kdf_fn_t)(const char *, int,
                        const unsigned char *, int,
                        unsigned char *, int);

/* ── Prototypes ───────────────────────────────────────────────────────────── */

/**
 * derive_key – PBKDF2-HMAC-SHA256 key derivation.
 * Conforms to kdf_fn_t so it can be passed as a function pointer.
 *
 * @param password  NUL-terminated passphrase
 * @param pass_len  byte length of password (excluding NUL)
 * @param salt      random salt buffer
 * @param salt_len  length of salt in bytes
 * @param key       output buffer (must be at least key_len bytes)
 * @param key_len   desired key length in bytes
 * @return          1 on success, 0 on failure (same convention as OpenSSL)
 */
int derive_key(const char *password, int pass_len,
               const unsigned char *salt, int salt_len,
               unsigned char *key, int key_len);

/**
 * base64_encode – encode arbitrary bytes to a NUL-terminated base64 string.
 * Caller is responsible for free()ing the returned buffer.
 *
 * @param input   raw byte buffer
 * @param len     number of bytes to encode
 * @return        heap-allocated, NUL-terminated base64 string, or NULL
 */
char *base64_encode(const unsigned char *input, size_t len);

/**
 * base64_decode – decode a base64 string back to raw bytes.
 * Caller is responsible for free()ing the returned buffer.
 *
 * @param input    NUL-terminated base64 string
 * @param out_len  set to the number of decoded bytes on success
 * @return         heap-allocated raw byte buffer, or NULL
 */
unsigned char *base64_decode(const char *input, size_t *out_len);

/**
 * read_password – prompt for and read a password without terminal echo.
 *
 * @param prompt   string printed to stdout before reading
 * @param buf      destination buffer
 * @param buf_len  size of buf (including space for NUL)
 * @return         number of characters read (>= 0), or -1 on error
 */
int read_password(const char *prompt, char *buf, size_t buf_len);

/**
 * crypto_error – print an error message to stderr then exit(EXIT_FAILURE).
 *
 * @param msg  human-readable error description
 */
void crypto_error(const char *msg);

#endif /* CRYPTO_COMMON_H */
