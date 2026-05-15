# XL-006 / RB-SECRETS-001 negative fixture.
# Key read from the environment, not bound to a literal.
class ApiClient
  API_KEY = ENV.fetch("OPENAI_API_KEY")
end
