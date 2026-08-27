require "jwt"

class TokenService
  def payload(token)
    JWT.decode(token, nil, false).first
  end

  def mint(claims)
    JWT.encode(claims, nil, "none")
  end
end
