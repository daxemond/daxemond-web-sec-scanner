import re
import base64
import json

JWT_REGEX = r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$"

def is_sensitive_cookie(name, value, cookie):
    patterns = [
        "session", "sess", "sid",
        "token", "auth", "jwt",
        "user", "uid", "email",
        "role", "permission",
        "key", "secret"
    ]

    # name-based detection
    if any(p in name for p in patterns):
        return True

    # value-based detection
    if any(p in value.lower() for p in patterns):
        return True

    # JWT detection
    if is_jwt(value):
        return True

    # long random-looking values (likely session tokens)
    if len(value) > 20 and re.match(r"^[A-Za-z0-9\-_]+$", value):
        return True

    return False

def analyze_jwt(token):
    header_b64, payload_b64, signature_b64 = token.split('.')

    signed = len(signature_b64) > 0

    return {
        "signed": signed,
        "alg": decode_jwt_header(header_b64).get("alg", None),
        "header": decode_jwt_header(header_b64),
        "payload": decode_jwt_payload(payload_b64)
    }



def decode_base64url(data):
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)

def decode_jwt_header(header_b64):
    return json.loads(decode_base64url(header_b64))

def decode_jwt_payload(payload_b64):
    return json.loads(decode_base64url(payload_b64))



def is_jwt(value):
    return re.match(JWT_REGEX, value) is not None

