# XL-004 / EX-TLS-VERIFY-001 positive fixture.
# HTTP client with peer verification disabled.
defmodule Client do
  def fetch(url), do: HTTPoison.get(url, [], ssl: [verify: :verify_none])
end
