require "jwt"

class TokenService
  def payload(token, key)
    JWT.decode(token, key, true, { algorithm: "HS256" }).first
  end

  def mint(claims, key)
    JWT.encode(claims, key, "HS256")
  end
end
