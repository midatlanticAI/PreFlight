import jwt

# Verified with an explicit key and a real algorithm.
def current_user(token, public_key):
    claims = jwt.decode(token, public_key, algorithms=["RS256"])
    return claims["sub"]


def mint(payload, secret):
    return jwt.encode(payload, secret, algorithm="HS256")


# Unrelated kwarg that happens to be spelled the same way.
def compress_block(data, algorithm="none"):
    return data
