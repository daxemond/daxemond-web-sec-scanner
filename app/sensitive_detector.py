import re

def is_sensitive(name, value):
    patterns = [
        r"csrf", r"token", r"auth", r"session",
        r"user", r"uid", r"id", r"email",
        r"jwt", r"key", r"secret", r"hash",
        r"salt", r"signature", r"sig",
        r"price", r"amount", r"fee",
        r"otp", r"pin", r"password", r"pass",
        r"credit", r"card", r"cvv", r"iban",
    ]

    # Check field name
    for p in patterns:
        if re.search(p, name, re.IGNORECASE):
            return True

    # Check field value
    for p in patterns:
        if re.search(p, value, re.IGNORECASE):
            return True

    # Check if value looks like a token
    if len(value) > 20 and re.match(r"^[A-Za-z0-9\-_]+$", value):
        return True

    return False
