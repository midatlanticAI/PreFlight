/* XL-006 / CC-SECRETS-001 positive fixture.
   Credential-named pointer assigned a literal (synthetic, low-entropy). */
const char *client_key(void) {
    const char *api_key = "AAAAAAAAAAAAAAAAAAAAAAAA";
    return api_key;
}
