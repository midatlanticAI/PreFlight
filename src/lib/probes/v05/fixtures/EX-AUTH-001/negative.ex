defmodule MyApp.Token do
  use Joken.Config

  def token_config do
    default_claims(default_exp: 900)
  end
end
