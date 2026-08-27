/* XL-013 / CC-AUTH-001 positive fixture. */
#include <jwt.h>
#include <openssl/evp.h>

int subject(const char *token, char **out) {
    jwt_t *jwt = NULL;
    /* NULL key: libjwt performs no validation beyond formatting. */
    if (jwt_decode(&jwt, token, NULL, 0) != 0) return -1;
    *out = jwt_get_grant(jwt, "sub");
    return 0;
}

int check_sig(EVP_MD_CTX *ctx, const unsigned char *sig, size_t len) {
    /* Wrong comparison: any non-1 value means failure. */
    if (EVP_DigestVerifyFinal(ctx, sig, len) != -1) return 1;
    return 0;
}
