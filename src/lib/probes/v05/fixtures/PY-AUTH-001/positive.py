import jwt
from jose import jwt as jose_jwt


def current_user(token):
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["sub"]


def mint(payload):
    return jwt.encode(payload, None, algorithm="none")


def loose(token, key):
    return jwt.decode(token, key, algorithms=["RS256", "none"])


def who(token):
    return jose_jwt.get_unverified_claims(token)["sub"]
