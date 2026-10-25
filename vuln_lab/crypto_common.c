/*
 * crypto_common.c
 *
 * Implementation of shared cryptographic helpers declared in crypto_common.h.
 *
 * Sources:
 *   OpenSSL documentation: https://www.openssl.org/docs/man3.0/
 *   RFC 2898 (PBKDF2):     https://www.rfc-editor.org/rfc/rfc2898
 *   NIST SP 800-38D (GCM): https://doi.org/10.6028/NIST.SP.800-38D
 */

#include "crypto_common.h"
#include <termios.h>
#include <unistd.h>

/* ── Error handler ────────────────────────────────────────────────────────── */

void crypto_error(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

/* ── Key derivation ───────────────────────────────────────────────────────── */

/*
 * derive_key
 *
 * Wraps PKCS5_PBKDF2_HMAC() with EVP_sha256() as the PRF.
 * PBKDF2_ITER is applied internally; see crypto_common.h for the value.
 *
 * Reference: OpenSSL man page PKCS5_PBKDF2_HMAC(3)
 */
int derive_key(const char *password, int pass_len,
               const unsigned char *salt, int salt_len,
               unsigned char *key, int key_len)
{
    return PKCS5_PBKDF2_HMAC(password, pass_len,
                              salt,     salt_len,
                              PBKDF2_ITER,
                              EVP_sha256(),
                              key_len, key);
}

/* ── Base64 ───────────────────────────────────────────────────────────────── */

/*
 * base64_encode
 *
 * Uses an OpenSSL BIO chain (BIO_f_base64 → BIO_s_mem).
 * BIO_FLAGS_BASE64_NO_NL suppresses line-wrapping so the result is one line.
 *
 * Reference: OpenSSL man page BIO_f_base64(3)
 */
char *base64_encode(const unsigned char *input, size_t len)
{
    BIO     *b64 = BIO_new(BIO_f_base64());
    BIO     *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;
    char    *result;

    if (!b64 || !mem)
        crypto_error("BIO allocation failed in base64_encode");

    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    if (BIO_write(b64, input, (int)len) <= 0)
        crypto_error("BIO_write failed in base64_encode");
    if (BIO_flush(b64) != 1)
        crypto_error("BIO_flush failed in base64_encode");

    BIO_get_mem_ptr(b64, &bptr);

    result = malloc(bptr->length + 1);
    if (!result)
        crypto_error("malloc failed in base64_encode");

    memcpy(result, bptr->data, bptr->length);
    result[bptr->length] = '\0';

    BIO_free_all(b64);   /* frees the whole chain including mem */
    return result;
}

/*
 * base64_decode
 *
 * Uses an OpenSSL BIO chain (BIO_f_base64 → BIO_s_mem).
 * The raw input length is a safe upper bound for the decoded buffer.
 *
 * Reference: OpenSSL man page BIO_f_base64(3)
 */
unsigned char *base64_decode(const char *input, size_t *out_len)
{
    size_t        in_len = strlen(input);
    BIO          *b64    = BIO_new(BIO_f_base64());
    BIO          *mem    = BIO_new_mem_buf(input, (int)in_len);
    unsigned char *result;
    int            decoded;

    if (!b64 || !mem)
        crypto_error("BIO allocation failed in base64_decode");

    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    result = malloc(in_len); /* upper bound: base64 expands by ~4/3 */
    if (!result)
        crypto_error("malloc failed in base64_decode");

    decoded = BIO_read(b64, result, (int)in_len);
    if (decoded < 0) {
        free(result);
        BIO_free_all(b64);
        crypto_error("BIO_read failed in base64_decode");
    }

    *out_len = (size_t)decoded;
    BIO_free_all(b64);
    return result;
}

/* ── Password reading ─────────────────────────────────────────────────────── */

/*
 * read_password
 *
 * Temporarily disables terminal echo using POSIX termios, reads a line,
 * then restores the original terminal settings.
 *
 * Reference: POSIX termios specification (The Open Group Base Specifications)
 */
int read_password(const char *prompt, char *buf, size_t buf_len)
{
    struct termios oldt, newt;
    size_t         len;
    int            is_tty = isatty(STDIN_FILENO);

    printf("%s", prompt);
    fflush(stdout);

    if (is_tty) {
        /* Interactive terminal: disable echo while reading */
        if (tcgetattr(STDIN_FILENO, &oldt) != 0)
            return -1;
        newt         = oldt;
        newt.c_lflag &= ~(tcflag_t)ECHO;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0)
            return -1;
    }

    if (!fgets(buf, (int)buf_len, stdin)) {
        if (is_tty)
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        return -1;
    }

    if (is_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        printf("\n");   /* newline after the hidden input */
    }

    /* Strip trailing newline */
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[--len] = '\0';
    }

    return (int)len;
}
