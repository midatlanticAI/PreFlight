package auth

import pdi.jwt.Jwt

object TokenService {
  def claims(token: String): String =
    Jwt.decodeRaw(token).get
}
