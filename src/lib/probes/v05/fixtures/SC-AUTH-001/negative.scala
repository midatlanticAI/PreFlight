package auth

import pdi.jwt.{Jwt, JwtAlgorithm}

object TokenService {
  def claims(token: String, key: String): String =
    Jwt.decodeRaw(token, key, Seq(JwtAlgorithm.HS256)).get
}
