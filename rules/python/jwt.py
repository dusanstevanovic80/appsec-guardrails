import jwt

SECRET = "change-me"


def current_user(token):
    # ruleid: jwt-signature-verification-disabled
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["sub"]


def current_user_safe(token):
    # ok: jwt-signature-verification-disabled
    claims = jwt.decode(token, SECRET, algorithms=["HS256"])
    return claims["sub"]
