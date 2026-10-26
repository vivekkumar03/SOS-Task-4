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
#include <limits.h>
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
    BIO     *b64 = NULL;
    BIO     *mem = NULL;
    BUF_MEM *bptr;
    char    *result;
    int      pushed = 0;

    if ((!input && len != 0) || len > INT_MAX)
        return NULL;

    b64 = BIO_new(BIO_f_base64());
    mem = BIO_new(BIO_s_mem());
    if (!b64 || !mem)
        goto error;

    if (!BIO_push(b64, mem))
        goto error;
    pushed = 1;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    if (BIO_write(b64, input, (int)len) <= 0)
        goto error;
    if (BIO_flush(b64) != 1)
        goto error;

    if (BIO_get_mem_ptr(b64, &bptr) <= 0 || !bptr)
        goto error;

    result = malloc(bptr->length + 1);
    if (!result)
        goto error;

    memcpy(result, bptr->data, bptr->length);
    result[bptr->length] = '\0';

    BIO_free_all(b64);   /* frees the whole chain including mem */
    return result;

error:
    if (pushed)
        BIO_free_all(b64);
    else {
        BIO_free(b64);
        BIO_free(mem);
    }
    return NULL;
}

/*
 * base64_decode
 *
 * Validates the alphabet and padding before decoding with EVP_DecodeBlock.
 *
 * Reference: OpenSSL man page BIO_f_base64(3)
 */
unsigned char *base64_decode(const char *input, size_t *out_len)
{
    size_t        in_len;
    size_t        padding = 0;
    size_t        i;
    unsigned char *result;
    int            decoded;

    if (!input || !out_len)
        return NULL;
    *out_len = 0;

    in_len = strlen(input);
    if (in_len == 0 || in_len % 4 != 0 || in_len > INT_MAX)
        return NULL;

    for (i = 0; i < in_len; i++) {
        unsigned char ch = (unsigned char)input[i];
        int is_alphabet = (ch >= 'A' && ch <= 'Z') ||
                          (ch >= 'a' && ch <= 'z') ||
                          (ch >= '0' && ch <= '9') || ch == '+' || ch == '/';

        if (is_alphabet) {
            if (padding != 0)
                return NULL;
        } else if (ch == '=' && i >= in_len - 2) {
            padding++;
        } else {
            return NULL;
        }
    }
    if (padding > 2 || (padding == 2 && input[in_len - 2] != '='))
        return NULL;

    result = malloc((in_len / 4) * 3);
    if (!result)
        return NULL;

    decoded = EVP_DecodeBlock(result, (const unsigned char *)input, (int)in_len);
    if (decoded < 0) {
        free(result);
        return NULL;
    }

    *out_len = (size_t)decoded - padding;
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
    size_t         len = 0;
    int            ch;
    int            got_input = 0;
    int            invalid = 0;
    int            read_error = 0;
    int            is_tty = isatty(STDIN_FILENO);

    if (!buf || buf_len == 0 || buf_len > INT_MAX)
        return -1;

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

    while ((ch = getchar()) != EOF && ch != '\n') {
        got_input = 1;
        if (ch == '\0' || len + 1 >= buf_len) {
            invalid = 1;
            continue;
        }
        buf[len++] = (char)ch;
    }
    buf[len] = '\0';
    if (ferror(stdin) || (!got_input && ch == EOF))
        read_error = 1;

    if (is_tty) {
        if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0)
            read_error = 1;
        printf("\n");   /* newline after the hidden input */
    }

    if (invalid || read_error) {
        OPENSSL_cleanse(buf, buf_len);
        return -1;
    }

    return (int)len;
}
