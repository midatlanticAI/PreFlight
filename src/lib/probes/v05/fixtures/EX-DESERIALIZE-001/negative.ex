# XL-001 / EX-DESERIALIZE-001 negative fixture.
# binary_to_term with [:safe]: no executable term construction.
defmodule Loader do
  def load(payload), do: :erlang.binary_to_term(payload, [:safe])
end
