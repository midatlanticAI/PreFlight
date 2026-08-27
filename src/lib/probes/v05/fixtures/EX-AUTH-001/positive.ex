defmodule MyApp.Token do
  use Joken.Config

  def token_config do
    default_claims(skip: [:exp, :nbf])
  end
end
