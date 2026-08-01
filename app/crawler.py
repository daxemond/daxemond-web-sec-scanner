import requests
from urllib.parse import urljoin, urlencode
from bs4 import BeautifulSoup
from sensitive_detector import is_sensitive
from detect_captcha import detect_captcha
from sensitive_cookie_detector import is_sensitive_cookie

# -----------------------------
# Basic Config
# -----------------------------
BASE_URL = "http://localhost:8080"   # Your test app
VISITED = set()
REPORT = []

# -----------------------------
# Payloads (Safe Demonstration)
# -----------------------------
SQLI_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "'--", "\"--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"/><img src=x onerror=alert(1)>"]

# -----------------------------
# Simple Crawler
# -----------------------------
def crawl(url):
    if url in VISITED:
        return
    VISITED.add(url)

    print(f"[Crawl] {url}")

    try:
        session = requests.session();
        res = session.get(url, timeout=5, verify="C:/Users/desmo/AppData/Local/mkcert/rootCA.pem")  # Disable SSL verification for localhost
    except Exception as e:
        print(f"[Error] Failed to fetch {url}: {e}")
        return

    #-- get sensitive cookies
    sensitive_cookies = get_sensitive_cookies(session)
    for cookie in sensitive_cookies:
        REPORT.append({
            "type": "Sensitive Cookie",
            "url": url,
            "cookie": cookie
        })
        print(f"[Sensitive Cookie] {cookie['name']} at {url}")


    soup = BeautifulSoup(res.text, "html.parser")

    # Extract links
    for link in soup.find_all("a"):
        href = link.get("href")
        if href and href.startswith("/"):
            crawl(urljoin(BASE_URL, href))

    # Test forms
    for form in soup.find_all("form"):
        test_form(url, form)

    # Check for CAPTCHA
    if detect_captcha(res.text):
        print(f"[CAPTCHA] CAPTCHA found at {url}")


# ------------------------
# hidden field check
# ------------------------
def get_hidden_fields(form):
    hidden_inputs = form.find_all("input", {"type": "hidden"})
    fields = {}

    for inp in hidden_inputs:
        name = inp.get("name", "")
        value = inp.get("value", "")
        fields[name] = value

    return fields

# -----------------------------
# Form Testing
# -----------------------------
def test_form(page_url, form):
    hidden_fields = get_hidden_fields(form)

    for name,value in hidden_fields.items():
        if is_sensitive(name,value):
            print(f"[Sensitive] Hidden field '{name}' with value '{value}' may contain sensitive data at {page_url}")

    action = form.get("action")
    method = form.get("method", "get").lower()

    target_url = urljoin(page_url, action)

    inputs = form.find_all("input")
    fields = {i.get("name"): "test" for i in inputs if i.get("name")}

    print(f"[Form] Testing {target_url}")

    # SQL Injection tests
    for payload in SQLI_PAYLOADS:
        test_payload(target_url, method, fields, payload, "SQL Injection")

    # XSS tests
    for payload in XSS_PAYLOADS:
        test_payload(target_url, method, fields, payload, "XSS")


#-----------------------------
# get sensitive hidden fields
#-----------------------------
def get_sensitive_cookies(session):
    sensitive = []

    for cookie in session.cookies:
        name = cookie.name.lower()
        value = cookie.value

        if is_sensitive_cookie(name, value, cookie):
            sensitive.append({
                "name": cookie.name,
                "value": cookie.value,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "secure": cookie.secure,
                "samesite": cookie.get_nonstandard_attr("SameSite")
            })

    return sensitive




# -----------------------------
# Payload Tester
# -----------------------------
def test_payload(url, method, fields, payload, test_type):
    test_fields = {k: payload for k in fields}

    try:
        if method == "post":
            res = requests.post(url, data=test_fields, timeout=5, verify="C:/Users/desmo/AppData/Local/mkcert/rootCA.pem")  # Disable SSL verification for localhost
        else:
            res = requests.get(url, params=test_fields, timeout=5, verify="C:/Users/desmo/AppData/Local/mkcert/rootCA.pem")  # Disable SSL verification for localhost
    except Exception as e:
        print(f"[Error] Failed to test payload at {url}: {e}")
        return

    if payload in res.text:
        REPORT.append({
            "type": test_type,
            "url": url,
            "payload": payload,
            "evidence": "Payload reflected in response"
        })
        print(f"[!] {test_type} found at {url}")


# -----------------------------
# Run Scanner
# -----------------------------
crawl(BASE_URL)

print("\n\n=== REPORT ===")
for r in REPORT:
    print(r)
