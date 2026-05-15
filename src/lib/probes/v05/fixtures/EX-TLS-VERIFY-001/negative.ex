# XL-004 / EX-TLS-VERIFY-001 negative fixture.
# Peer verification on with a CA store.
defmodule Client do
  def fetch(url) do
    HTTPoison.get(url, [], ssl: [verify: :verify_peer, cacertfile: CAStore.file_path()])
  end
end
