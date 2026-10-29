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

#define _POSIX_C_SOURCE 200809L
#include "crypto_common.h"
#include <limits.h>
#include <signal.h>
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
 * The supplied iteration count is checked against the supported policy.
 *
 * Reference: OpenSSL man page PKCS5_PBKDF2_HMAC(3)
 */
static void store_u32(unsigned char *output, uint32_t value)
{
    output[0] = (unsigned char)(value >> 24);
    output[1] = (unsigned char)(value >> 16);
    output[2] = (unsigned char)(value >> 8);
    output[3] = (unsigned char)value;
}

static uint32_t load_u32(const unsigned char *input)
{
    return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] << 8) | (uint32_t)input[3];
}

void make_header(unsigned char *header, uint32_t message_len)
{
    memcpy(header, FORMAT_MAGIC, 4);
    header[4] = FORMAT_VERSION;
    header[5] = KDF_PBKDF2_SHA256;
    store_u32(header + 6, PBKDF2_ITER);
    store_u32(header + 10, message_len);
}

int parse_header(const unsigned char *header, size_t decoded_len, int *iterations)
{
    uint32_t stored_iterations;
    uint32_t message_len;

    if (!header || !iterations || decoded_len <= HEADER_LEN ||
        memcmp(header, FORMAT_MAGIC, 4) != 0 || header[4] != FORMAT_VERSION ||
        header[5] != KDF_PBKDF2_SHA256)
        return 0;
    stored_iterations = load_u32(header + 6);
    message_len = load_u32(header + 10);
    if (stored_iterations < PBKDF2_ITER || stored_iterations > MAX_PBKDF2_ITER ||
        message_len == 0 || message_len >= MAX_MSG_LEN ||
        decoded_len != HEADER_LEN + (size_t)message_len)
        return 0;
    *iterations = (int)stored_iterations;
    return 1;
}

int derive_key(const char *password, int pass_len,
               const unsigned char *salt, int salt_len,
               unsigned char *key, int key_len, int iterations)
{
    if (iterations < PBKDF2_ITER || iterations > MAX_PBKDF2_ITER)
        return 0;
    return PKCS5_PBKDF2_HMAC(password, pass_len,
                              salt,     salt_len,
                              iterations,
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
    char          *canonical;
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

    canonical = base64_encode(result, (size_t)decoded - padding);
    if (!canonical || strcmp(canonical, input) != 0) {
        free(canonical);
        free(result);
        return NULL;
    }
    free(canonical);
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
static struct termios saved_terminal;
static volatile sig_atomic_t terminal_hidden;

static void password_signal(int signal_number)
{
    if (terminal_hidden)
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_terminal);
    _exit(128 + signal_number);
}

int read_password(const char *prompt, char *buf, size_t buf_len)
{
    struct termios oldt, newt;
    const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP};
    struct sigaction action, previous[5];
    sigset_t blocked, previous_mask;
    size_t installed = 0;
    size_t         len = 0;
    int            ch;
    int            got_input = 0;
    int            invalid = 0;
    int            read_error = 0;
    int            is_tty = isatty(STDIN_FILENO);

    if (!buf || buf_len == 0 || buf_len > INT_MAX)
        return -1;

    if (is_tty) {
        if (tcgetattr(STDIN_FILENO, &oldt) != 0)
            return -1;
        sigemptyset(&blocked);
        for (size_t index = 0; index < 5; index++)
            sigaddset(&blocked, signals[index]);
        if (sigprocmask(SIG_BLOCK, &blocked, &previous_mask) != 0)
            return -1;
        memset(&action, 0, sizeof(action));
        action.sa_handler = password_signal;
        action.sa_mask = blocked;
        saved_terminal = oldt;
        for (installed = 0; installed < 5; installed++) {
            if (sigaction(signals[installed], &action, &previous[installed]) != 0)
                break;
        }
        newt         = oldt;
        newt.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);
        if (installed != 5 || tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
            while (installed > 0) {
                installed--;
                sigaction(signals[installed], &previous[installed], NULL);
            }
            sigprocmask(SIG_SETMASK, &previous_mask, NULL);
            return -1;
        }
        terminal_hidden = 1;
        sigprocmask(SIG_SETMASK, &previous_mask, NULL);
    }

    printf("%s", prompt);
    fflush(stdout);

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
        sigprocmask(SIG_BLOCK, &blocked, NULL);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0)
            read_error = 1;
        terminal_hidden = 0;
        for (size_t index = 0; index < 5; index++)
            sigaction(signals[index], &previous[index], NULL);
        sigprocmask(SIG_SETMASK, &previous_mask, NULL);
        printf("\n");   /* newline after the hidden input */
    }

    if (invalid || read_error) {
        OPENSSL_cleanse(buf, buf_len);
        return read_error ? -1 : PASSWORD_INVALID;
    }

    return (int)len;
}
