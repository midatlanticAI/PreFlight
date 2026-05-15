/* XL-006 / CC-SECRETS-001 negative fixture.
   Key read from the environment, not bound to a literal. */
const char *client_key(void) {
    const char *api_key = getenv("OPENAI_API_KEY");
    return api_key;
}
