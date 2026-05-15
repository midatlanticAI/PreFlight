# XL-006 / EX-SECRETS-001 negative fixture.
# secret_key_base read from the environment at runtime.
import Config

config :myapp, MyApp.Endpoint,
  secret_key_base: System.fetch_env!("SECRET_KEY_BASE")
