# XL-002 / EX-SQL-RAW-001 negative fixture.
# Pinned parameter: fragment("name = ?", ^name).
defmodule UserRepo do
  import Ecto.Query
  def find(name) do
    from(u in "users", where: fragment("name = ?", ^name))
  end
end
