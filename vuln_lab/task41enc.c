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

#define _POSIX_C_SOURCE 200809L
#include "crypto_common.h"
#include <unistd.h>

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
    int            input_char;
    int            message_too_long = 0;
    int            output_fd = -1;
    int            temp_created = 0;
    int            write_failed = 0;
    int            exit_code = EXIT_FAILURE;
    const char    *error_message = NULL;
    char           temp_path[] = OUTPUT_FILE ".XXXXXX";

    /* ── (1) Read plaintext message ──────────────────────────────────────── */
    printf("Enter message to encrypt: ");
    fflush(stdout);
    msg_len = 0;
    while ((input_char = getchar()) != EOF && input_char != '\n') {
        if (input_char == '\0' || msg_len + 1 >= sizeof(message)) {
            message_too_long = 1;
            continue;
        }
        message[msg_len++] = (char)input_char;
    }
    message[msg_len] = '\0';
    if (ferror(stdin) || (input_char == EOF && msg_len == 0)) {
        error_message = "Failed to read message";
        goto cleanup;
    }
    if (message_too_long) {
        error_message = "Message is too long or contains a NUL byte";
        goto cleanup;
    }
    if (msg_len == 0) {
        error_message = "Empty message – nothing to encrypt";
        goto cleanup;
    }

    /* ── (1.2) Read password ─────────────────────────────────────────────── */
    if (read_password("Enter password: ", password, sizeof(password)) <= 0) {
        error_message = "Empty, overlong, or unreadable password";
        goto cleanup;
    }

    /* ── Generate random salt and IV ─────────────────────────────────────── */
    if (RAND_bytes(salt, SALT_LEN) != 1 || RAND_bytes(iv, IV_LEN) != 1) {
        error_message = "Cryptographic random generation failed";
        goto cleanup;
    }

    /* ── Derive AES-256 key via PBKDF2-HMAC-SHA256 ──────────────────────── */
    /*
     * kdf is a kdf_fn_t function pointer – allows swapping the KDF strategy
     * without changing the call site below.
     */
    kdf_fn_t kdf = derive_key;
    if (kdf(password, (int)strlen(password),
            salt, SALT_LEN,
            key, KEY_LEN) != 1) {
        error_message = "PBKDF2 key derivation failed";
        goto cleanup;
    }

    /* ── AES-256-GCM encryption ──────────────────────────────────────────── */
    /*
     * GCM ciphertext is the same length as plaintext (stream-mode cipher).
     * EVP_MAX_BLOCK_LENGTH is added as a safe margin for EVP_EncryptFinal_ex.
     * Reference: OpenSSL man page EVP_EncryptInit(3)
     */
    ciphertext = malloc(msg_len + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext) {
        error_message = "malloc failed for ciphertext buffer";
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        error_message = "EVP_CIPHER_CTX_new failed";
        goto cleanup;
    }

    /* Step 1: select cipher, no key/IV yet */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        error_message = "EVP_EncryptInit_ex (cipher selection) failed";
        goto cleanup;
    }

    /* Step 2: set custom IV length (12 bytes is NIST-recommended for GCM) */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) {
        error_message = "Setting GCM IV length failed";
        goto cleanup;
    }

    /* Step 3: supply key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        error_message = "EVP_EncryptInit_ex (key+IV) failed";
        goto cleanup;
    }

    /* Step 4: encrypt plaintext */
    if (EVP_EncryptUpdate(ctx, ciphertext, &ct_len,
                          (const unsigned char *)message, (int)msg_len) != 1) {
        error_message = "EVP_EncryptUpdate failed";
        goto cleanup;
    }

    /* Step 5: finalize (flushes any buffered data; 0 extra bytes for GCM) */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ct_len, &final_len) != 1) {
        error_message = "EVP_EncryptFinal_ex failed";
        goto cleanup;
    }
    ct_len += final_len;

    /* Step 6: retrieve the GCM authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        error_message = "Retrieving GCM tag failed";
        goto cleanup;
    }

    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* ── Assemble binary blob: [salt | IV | tag | ciphertext] ───────────── */
    total_len = SALT_LEN + IV_LEN + TAG_LEN + (size_t)ct_len;
    file_buf  = malloc(total_len);
    if (!file_buf) {
        error_message = "malloc failed for file buffer";
        goto cleanup;
    }

    memcpy(file_buf,                              salt,       SALT_LEN);
    memcpy(file_buf + SALT_LEN,                   iv,         IV_LEN);
    memcpy(file_buf + SALT_LEN + IV_LEN,          tag,        TAG_LEN);
    memcpy(file_buf + SALT_LEN + IV_LEN + TAG_LEN, ciphertext, (size_t)ct_len);

    /* ── Base64-encode and write to OUTPUT_FILE ──────────────────────────── */
    b64_output = base64_encode(file_buf, total_len);
    if (!b64_output) {
        error_message = "Base64 encoding failed";
        goto cleanup;
    }

    output_fd = mkstemp(temp_path);
    if (output_fd < 0) {
        error_message = "Failed to open temporary ciphertext file";
        goto cleanup;
    }
    temp_created = 1;
    fp = fdopen(output_fd, "w");
    if (!fp) {
        close(output_fd);
        output_fd = -1;
        error_message = "Failed to open temporary ciphertext stream";
        goto cleanup;
    }
    output_fd = -1;
    write_failed = fprintf(fp, "%s\n", b64_output) < 0;
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0)
        write_failed = 1;
    if (fclose(fp) != 0)
        write_failed = 1;
    fp = NULL;
    if (write_failed) {
        error_message = "Failed to write ciphertext";
        goto cleanup;
    }
    if (rename(temp_path, OUTPUT_FILE) != 0) {
        error_message = "Failed to replace " OUTPUT_FILE;
        goto cleanup;
    }
    temp_created = 0;

    printf("Encrypted message written to " OUTPUT_FILE "\n");
    printf("  Salt length : %d bytes\n",   SALT_LEN);
    printf("  IV length   : %d bytes\n",   IV_LEN);
    printf("  Tag length  : %d bytes\n",   TAG_LEN);
    printf("  Ciphertext  : %d bytes\n",   ct_len);
    printf("  PBKDF2 iter : %d\n",         PBKDF2_ITER);

    exit_code = EXIT_SUCCESS;

cleanup:
    if (fp)
        fclose(fp);
    if (output_fd >= 0)
        close(output_fd);
    if (temp_created)
        unlink(temp_path);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key,      KEY_LEN);
    OPENSSL_cleanse(password, MAX_PASS_LEN);
    OPENSSL_cleanse(message,  MAX_MSG_LEN);
    OPENSSL_cleanse(tag,      TAG_LEN);
    if (file_buf)
        OPENSSL_cleanse(file_buf, total_len);
    free(ciphertext);
    free(file_buf);
    free(b64_output);

    if (error_message)
        fprintf(stderr, "Error: %s\n", error_message);
    return exit_code;
}
