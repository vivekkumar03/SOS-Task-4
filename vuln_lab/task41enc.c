/*
 * task41enc.c
 *
 * Reads a plaintext message and a password from the user, then:
 *   1. Generates a random 16-byte salt and 12-byte IV.
 *   2. Derives a 256-bit AES key via PBKDF2-HMAC-SHA256.
 *   3. Encrypts the message with AES-256-GCM, capturing the 16-byte tag.
 *   4. Concatenates [salt | IV | tag | ciphertext] and writes the
 *      base64 encoding to OUTPUT_FILE ("text.ct").
 *
 * Crypto algorithms:
 *   Key derivation : PBKDF2-HMAC-SHA256  (RFC 2898)
 *   Encryption     : AES-256-GCM         (NIST SP 800-38D)
 *   Encoding       : Base64              (RFC 4648)
 *
 * Compile: see Makefile or build.sh
 */

#include "crypto_common.h"

int main(void)
{
    /* ── Variables ────────────────────────────────────────────────────────── */
    unsigned char  salt[SALT_LEN];
    unsigned char  iv[IV_LEN];
    unsigned char  key[KEY_LEN];
    unsigned char  tag[TAG_LEN];
    char           message[MAX_MSG_LEN];
    char           password[MAX_PASS_LEN];
    unsigned char *ciphertext  = NULL;
    unsigned char *file_buf    = NULL;
    char          *b64_output  = NULL;
    FILE          *fp          = NULL;
    EVP_CIPHER_CTX *ctx        = NULL;
    int            ct_len      = 0;
    int            final_len   = 0;
    size_t         msg_len;
    size_t         total_len;

    /* ── (1) Read plaintext message ──────────────────────────────────────── */
    printf("Enter message to encrypt: ");
    fflush(stdout);
    if (!fgets(message, sizeof(message), stdin))
        crypto_error("Failed to read message");

    msg_len = strlen(message);
    if (msg_len > 0 && message[msg_len - 1] == '\n') {
        message[--msg_len] = '\0';
    }
    if (msg_len == 0)
        crypto_error("Empty message – nothing to encrypt");

    /* ── (1.2) Read password ─────────────────────────────────────────────── */
    if (read_password("Enter password: ", password, sizeof(password)) <= 0)
        crypto_error("Empty or unreadable password");

    /* ── Generate random salt and IV ─────────────────────────────────────── */
    /*
     * RAND_bytes() uses the OS entropy source (e.g. /dev/urandom on Linux).
     * Reference: OpenSSL man page RAND_bytes(3)
     */
    /* LAB FLAW: fixed salt and IV make repeated encryptions deterministic;
       reusing a GCM IV with the same key compromises security. */
    memset(salt, 0x41, SALT_LEN);
    memset(iv,   0x42, IV_LEN);

    /* ── Derive AES-256 key via PBKDF2-HMAC-SHA256 ──────────────────────── */
    /*
     * kdf is a kdf_fn_t function pointer – allows swapping the KDF strategy
     * without changing the call site below.
     */
    kdf_fn_t kdf = derive_key;
    if (kdf(password, (int)strlen(password),
            salt, SALT_LEN,
            key, KEY_LEN) != 1)
        crypto_error("PBKDF2 key derivation failed");

    /* ── AES-256-GCM encryption ──────────────────────────────────────────── */
    /*
     * GCM ciphertext is the same length as plaintext (stream-mode cipher).
     * EVP_MAX_BLOCK_LENGTH is added as a safe margin for EVP_EncryptFinal_ex.
     * Reference: OpenSSL man page EVP_EncryptInit(3)
     */
    ciphertext = malloc(msg_len + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext)
        crypto_error("malloc failed for ciphertext buffer");

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        crypto_error("EVP_CIPHER_CTX_new failed");

    /* Step 1: select cipher, no key/IV yet */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        crypto_error("EVP_EncryptInit_ex (cipher selection) failed");

    /* Step 2: set custom IV length (12 bytes is NIST-recommended for GCM) */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1)
        crypto_error("Setting GCM IV length failed");

    /* Step 3: supply key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        crypto_error("EVP_EncryptInit_ex (key+IV) failed");

    /* Step 4: encrypt plaintext */
    if (EVP_EncryptUpdate(ctx, ciphertext, &ct_len,
                          (const unsigned char *)message, (int)msg_len) != 1)
        crypto_error("EVP_EncryptUpdate failed");

    /* Step 5: finalize (flushes any buffered data; 0 extra bytes for GCM) */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ct_len, &final_len) != 1)
        crypto_error("EVP_EncryptFinal_ex failed");
    ct_len += final_len;

    /* Step 6: retrieve the GCM authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
        crypto_error("Retrieving GCM tag failed");

    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* ── Assemble binary blob: [salt | IV | tag | ciphertext] ───────────── */
    total_len = SALT_LEN + IV_LEN + TAG_LEN + (size_t)ct_len;
    file_buf  = malloc(total_len);
    if (!file_buf)
        crypto_error("malloc failed for file buffer");

    memcpy(file_buf,                              salt,       SALT_LEN);
    memcpy(file_buf + SALT_LEN,                   iv,         IV_LEN);
    memcpy(file_buf + SALT_LEN + IV_LEN,          tag,        TAG_LEN);
    memcpy(file_buf + SALT_LEN + IV_LEN + TAG_LEN, ciphertext, (size_t)ct_len);

    /* ── Base64-encode and write to OUTPUT_FILE ──────────────────────────── */
    b64_output = base64_encode(file_buf, total_len);

    fp = fopen(OUTPUT_FILE, "w");
    if (!fp)
        crypto_error("Failed to open " OUTPUT_FILE " for writing");

    fprintf(fp, "%s\n", b64_output);
    fclose(fp);
    fp = NULL;

    printf("Encrypted message written to " OUTPUT_FILE "\n");
    printf("  Salt length : %d bytes\n",   SALT_LEN);
    printf("  IV length   : %d bytes\n",   IV_LEN);
    printf("  Tag length  : %d bytes\n",   TAG_LEN);
    printf("  Ciphertext  : %d bytes\n",   ct_len);
    printf("  PBKDF2 iter : %d\n",         PBKDF2_ITER);

    /* ── Cleanup: free memory and erase sensitive data ───────────────────── */
    /*
     * OPENSSL_cleanse() is guaranteed not to be optimised away by the compiler
     * (unlike memset), making it safe for clearing cryptographic material.
     * Reference: OpenSSL man page OPENSSL_cleanse(3)
     */
    OPENSSL_cleanse(key,      KEY_LEN);
    OPENSSL_cleanse(password, MAX_PASS_LEN);
    OPENSSL_cleanse(message,  MAX_MSG_LEN);
    OPENSSL_cleanse(tag,      TAG_LEN);
    free(ciphertext);
    free(file_buf);
    free(b64_output);

    return EXIT_SUCCESS;
}
