/*
 * task41dec.c
 *
 * Reads the base64-encoded ciphertext file (OUTPUT_FILE = "text.ct"),
 * prompts the user for the password, and:
 *   1. Base64-decodes the file content.
 *   2. Splits the binary blob into [salt | IV | tag | ciphertext].
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

#include "crypto_common.h"

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
    long           file_size;
    size_t         b64_len;
    size_t         plaintext_capacity = 0;
    int            ct_len;
    int            exit_code = EXIT_FAILURE;
    const char    *error_message = NULL;

    /* Pointers into file_buf – no separate allocation needed */
    unsigned char *salt;
    unsigned char *iv;
    unsigned char *tag;
    unsigned char *ciphertext;

    /* ── Read ciphertext file ────────────────────────────────────────────── */
    fp = fopen(OUTPUT_FILE, "r");
    if (!fp) {
        error_message = "Cannot open " OUTPUT_FILE " - has the file been encrypted yet?";
        goto cleanup;
    }

    /* Determine file size and read entire content */
    if (fseek(fp, 0, SEEK_END) != 0) {
        error_message = "Failed to seek in " OUTPUT_FILE;
        goto cleanup;
    }
    file_size = ftell(fp);
    if (file_size <= 0 || file_size > (long)(MAX_B64_LEN + 2)) {
        error_message = "Invalid or oversized " OUTPUT_FILE;
        goto cleanup;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        error_message = "Failed to seek in " OUTPUT_FILE;
        goto cleanup;
    }

    b64_line = malloc((size_t)file_size + 1);
    if (!b64_line) {
        error_message = "malloc failed for base64 buffer";
        goto cleanup;
    }

    if (fread(b64_line, 1, (size_t)file_size, fp) != (size_t)file_size) {
        error_message = "Failed to read " OUTPUT_FILE;
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

    /* Strip trailing whitespace / newlines */
    b64_len = strlen(b64_line);
    while (b64_len > 0 &&
           (b64_line[b64_len - 1] == '\n' || b64_line[b64_len - 1] == '\r'))
    {
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

    if (decoded_len <= HEADER_LEN || decoded_len > HEADER_LEN + MAX_MSG_LEN) {
        error_message = "Invalid ciphertext length";
        goto cleanup;
    }

    /* ── Split blob into components ──────────────────────────────────────── */
    salt       = file_buf;
    iv         = file_buf + SALT_LEN;
    tag        = file_buf + SALT_LEN + IV_LEN;
    ciphertext = file_buf + SALT_LEN + IV_LEN + TAG_LEN;
    ct_len     = (int)(decoded_len - HEADER_LEN);

    /* ── Read password ───────────────────────────────────────────────────── */
    if (read_password("Enter password: ", password, sizeof(password)) <= 0) {
        error_message = "Empty, overlong, or unreadable password";
        goto cleanup;
    }

    /* ── Derive AES-256 key via PBKDF2-HMAC-SHA256 ──────────────────────── */
    /*
     * kdf_fn_t function pointer – identical strategy as in task41enc.c,
     * keeping the call site decoupled from the concrete implementation.
     */
    kdf_fn_t kdf = derive_key;
    if (kdf(password, (int)strlen(password),
            salt, SALT_LEN,
            key, KEY_LEN) != 1) {
        error_message = "PBKDF2 key derivation failed";
        goto cleanup;
    }

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

    /* Step 1: select cipher */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        error_message = "EVP_DecryptInit_ex (cipher selection) failed";
        goto cleanup;
    }

    /* Step 2: set IV length */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) {
        error_message = "Setting GCM IV length failed";
        goto cleanup;
    }

    /* Step 3: supply key and IV */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        error_message = "EVP_DecryptInit_ex (key+IV) failed";
        goto cleanup;
    }

    /* Step 4: set the expected GCM tag BEFORE finalising */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1) {
        error_message = "Setting GCM tag failed";
        goto cleanup;
    }

    /* Step 5: decrypt */
    if (EVP_DecryptUpdate(ctx, plaintext, &pt_len, ciphertext, ct_len) != 1) {
        error_message = "EVP_DecryptUpdate failed";
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + pt_len, &final_len) != 1) {
        error_message = "Authentication failed: wrong password or modified ciphertext";
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
