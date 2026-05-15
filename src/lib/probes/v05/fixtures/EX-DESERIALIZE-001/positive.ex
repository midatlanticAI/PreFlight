# XL-001 / EX-DESERIALIZE-001 positive fixture.
# binary_to_term without [:safe]: arbitrary term construction.
defmodule Loader do
  def load(payload), do: :erlang.binary_to_term(payload)
end
