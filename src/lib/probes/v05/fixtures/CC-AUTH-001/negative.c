/* XL-013 / CC-AUTH-001 negative fixture. */
#include <jwt.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

int subject(const char *token, const unsigned char *key, int key_len, char **out) {
    jwt_t *jwt = NULL;
    if (jwt_decode(&jwt, token, key, key_len) != 0) return -1;
    *out = jwt_get_grant(jwt, "sub");
    return 0;
}

int check_sig(EVP_MD_CTX *ctx, const unsigned char *sig, size_t len) {
    /* Correct: OpenSSL returns 1 for success and nothing else counts. */
    return EVP_DigestVerifyFinal(ctx, sig, len) == 1;
}

int compare_tag(const unsigned char *a, const unsigned char *b, size_t n) {
    return CRYPTO_memcmp(a, b, n) == 0;
}
