import re

def detect_captcha(html):
    patterns = [
        r"google\.com/recaptcha",     # reCAPTCHA
        r"g-recaptcha",               # reCAPTCHA div
        r"grecaptcha",                # JS API
        r"hcaptcha\.com",             # hCaptcha
        r"h-captcha",                 # hCaptcha div
        r"cf-turnstile",              # Cloudflare Turnstile
        r"challenges.cloudflare.com", # Turnstile script
        r"captcha",                   # generic image/text
        r"verification code",         # generic
        r"robot check",               # generic
    ]

    for p in patterns:
        if re.search(p, html, re.IGNORECASE):
            return True

    return False
