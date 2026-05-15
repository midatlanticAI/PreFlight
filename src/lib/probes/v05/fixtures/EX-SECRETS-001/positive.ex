# XL-006 / EX-SECRETS-001 positive fixture.
# Phoenix secret_key_base as a committed literal (synthetic).
import Config

config :myapp, MyApp.Endpoint,
  secret_key_base: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
