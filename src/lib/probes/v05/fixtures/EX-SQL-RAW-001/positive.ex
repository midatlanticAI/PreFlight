# XL-002 / EX-SQL-RAW-001 positive fixture.
# fragment/1 does not escape #{} interpolation.
defmodule UserRepo do
  import Ecto.Query
  def find(name) do
    from(u in "users", where: fragment("name = '#{name}'"))
  end
end
