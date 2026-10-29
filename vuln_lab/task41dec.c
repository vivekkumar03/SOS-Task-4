/*
 * task41dec.c
 *
 * Reads the base64-encoded ciphertext file (OUTPUT_FILE = "text.ct"),
 * prompts the user for the password, and:
 *   1. Base64-decodes the file content.
 *   2. Validates the versioned header and splits the remaining fields.
 *   3. Derives the AES key via PBKDF2-HMAC-SHA256 using the stored salt.
 *   4. Decrypts with AES-256-GCM, verifying the authentication tag.
 *   5. Prints the recovered plaintext to stdout.
 *
 * A tag mismatch (wrong password or tampered ciphertext) is detected and
 * reported by EVP_DecryptFinal_ex returning 0.
 *
 * Crypto algorithms:
 *   Key derivation : PBKDF2-HMAC-SHA256  (RFC 2898)
 *   Decryption     : AES-256-GCM         (NIST SP 800-38D)
 *   Encoding       : Base64              (RFC 4648)
 *
 * Compile: see Makefile or build.sh
 */

#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include "crypto_common.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    /* ── Variables ────────────────────────────────────────────────────────── */
    unsigned char  key[KEY_LEN];
    char           password[MAX_PASS_LEN];
    char          *b64_line    = NULL;
    unsigned char *file_buf    = NULL;
    unsigned char *plaintext   = NULL;
    FILE          *fp          = NULL;
    EVP_CIPHER_CTX *ctx        = NULL;
    size_t         decoded_len = 0;
    int            pt_len      = 0;
    int            final_len   = 0;
    int            aad_len     = 0;
    int            iterations  = 0;
    int            input_fd    = -1;
    struct stat    input_info;
    long           file_size;
    size_t         b64_len;
    size_t         plaintext_capacity = 0;
    int            ct_len;
    int            exit_code = EXIT_FAILURE;
    int            authenticated = 0;
    const char    *error_message = NULL;

    /* Pointers into file_buf – no separate allocation needed */
    unsigned char *salt;
    unsigned char *iv;
    unsigned char *tag;
    unsigned char *ciphertext;

    if (setvbuf(stdin, NULL, _IONBF, 0) != 0) {
        error_message = "Cannot disable input buffering";
        goto cleanup;
    }
    /* ── Read ciphertext file ────────────────────────────────────────────── */
    input_fd = open(OUTPUT_FILE, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (input_fd < 0 || fstat(input_fd, &input_info) != 0 ||
        !S_ISREG(input_info.st_mode)) {
        error_message = "Cannot open a regular, non-symlink " OUTPUT_FILE;
        goto cleanup;
    }
    fp = fdopen(input_fd, "r");
    if (!fp) {
        error_message = "Cannot open ciphertext stream";
        goto cleanup;
    }
    input_fd = -1;

    if (input_info.st_size <= 0 || input_info.st_size > MAX_B64_LEN + 2) {
        error_message = "Invalid or oversized " OUTPUT_FILE;
        goto cleanup;
    }
    file_size = (long)input_info.st_size;

    b64_line = malloc((size_t)file_size + 1);
    if (!b64_line) {
        error_message = "malloc failed for base64 buffer";
        goto cleanup;
    }

    if (fread(b64_line, 1, (size_t)file_size, fp) != (size_t)file_size) {
        error_message = "Failed to read " OUTPUT_FILE;
        goto cleanup;
    }
    if (fgetc(fp) != EOF || ferror(fp)) {
        error_message = "Ciphertext changed during reading or contains extra bytes";
        goto cleanup;
    }

    if (memchr(b64_line, '\0', (size_t)file_size) != NULL) {
        error_message = "Invalid NUL byte in " OUTPUT_FILE;
        goto cleanup;
    }

    b64_line[file_size] = '\0';
    if (fclose(fp) != 0) {
        fp = NULL;
        error_message = "Failed to close " OUTPUT_FILE;
        goto cleanup;
    }
    fp = NULL;

    b64_len = (size_t)file_size;
    if (b64_len > 0 && b64_line[b64_len - 1] == '\n') {
        b64_line[--b64_len] = '\0';
        if (b64_len > 0 && b64_line[b64_len - 1] == '\r')
            b64_line[--b64_len] = '\0';
    }

    /* ── Base64-decode ───────────────────────────────────────────────────── */
    file_buf = base64_decode(b64_line, &decoded_len);
    free(b64_line);
    b64_line = NULL;
    if (!file_buf) {
        error_message = "Invalid or undecodable Base64 input";
        goto cleanup;
    }

    if (!parse_header(file_buf, decoded_len, &iterations)) {
        error_message = "Invalid header, unsupported format/KDF, or ciphertext length";
        goto cleanup;
    }

    /* ── Split blob into components ──────────────────────────────────────── */
    salt       = file_buf + METADATA_LEN;
    iv         = file_buf + METADATA_LEN + SALT_LEN;
    tag        = file_buf + AAD_LEN;
    ciphertext = file_buf + HEADER_LEN;
    ct_len     = (int)(decoded_len - HEADER_LEN);

    kdf_fn_t kdf = derive_key;

    /* ── AES-256-GCM decryption ──────────────────────────────────────────── */
    /*
     * One extra byte is allocated so the plaintext can be NUL-terminated
     * and printed safely as a C string.
     * Reference: OpenSSL man page EVP_EncryptInit(3)
     */
    plaintext = malloc((size_t)ct_len + 1);
    if (!plaintext) {
        error_message = "malloc failed for plaintext buffer";
        goto cleanup;
    }
    plaintext_capacity = (size_t)ct_len + 1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        error_message = "EVP_CIPHER_CTX_new failed";
        goto cleanup;
    }

    for (int attempt = 0; attempt < MAX_PASSWORD_ATTEMPTS; attempt++) {
        int password_len;

        if (EVP_CIPHER_CTX_reset(ctx) != 1) {
            error_message = "Resetting decryption state failed";
            goto cleanup;
        }
        OPENSSL_cleanse(key, sizeof(key));
        OPENSSL_cleanse(password, sizeof(password));
        OPENSSL_cleanse(plaintext, plaintext_capacity);
        pt_len = 0;
        final_len = 0;
        aad_len = 0;

        password_len = read_password("Enter password: ", password, sizeof(password));
        if (password_len == -1) {
            error_message = "Password input ended or could not be read";
            goto cleanup;
        }
        if (password_len <= 0) {
            fprintf(stderr, "Empty or invalid password. Try again.\n");
            continue;
        }
        if (kdf(password, password_len, salt, SALT_LEN,
                key, KEY_LEN, iterations) != 1) {
            error_message = "PBKDF2 key derivation failed";
            goto cleanup;
        }
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
            error_message = "EVP_DecryptInit_ex (cipher selection) failed";
            goto cleanup;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) {
            error_message = "Setting GCM IV length failed";
            goto cleanup;
        }
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
            error_message = "EVP_DecryptInit_ex (key+IV) failed";
            goto cleanup;
        }
        if (EVP_DecryptUpdate(ctx, NULL, &aad_len, file_buf, AAD_LEN) != 1) {
            error_message = "Authenticating file header failed";
            goto cleanup;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1) {
            error_message = "Setting GCM tag failed";
            goto cleanup;
        }
        if (EVP_DecryptUpdate(ctx, plaintext, &pt_len, ciphertext, ct_len) != 1) {
            error_message = "EVP_DecryptUpdate failed";
            goto cleanup;
        }
        if (EVP_DecryptFinal_ex(ctx, plaintext + pt_len, &final_len) != 1) {
            OPENSSL_cleanse(key, sizeof(key));
            OPENSSL_cleanse(password, sizeof(password));
            OPENSSL_cleanse(plaintext, plaintext_capacity);
            fprintf(stderr, "Authentication failed: wrong password or modified ciphertext. Try again.\n");
            continue;
        }
        authenticated = 1;
        break;
    }
    if (!authenticated) {
        error_message = "Password attempt limit reached";
        goto cleanup;
    }

    pt_len += final_len;
    plaintext[pt_len] = '\0';   /* NUL-terminate for printf */

    /* ── Output decrypted message ─────────────────────────────────────────── */
    printf("Decrypted message: %s\n", plaintext);

    exit_code = EXIT_SUCCESS;

cleanup:
    if (fp)
        fclose(fp);
    if (input_fd >= 0)
        close(input_fd);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key,      KEY_LEN);
    OPENSSL_cleanse(password, MAX_PASS_LEN);
    if (plaintext)
        OPENSSL_cleanse(plaintext, plaintext_capacity);
    free(plaintext);
    free(b64_line);
    free(file_buf);

    if (error_message)
        fprintf(stderr, "Error: %s\n", error_message);
    return exit_code;
}
