import requests


TARGET_URL = "http://127.0.0.1:8000"

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def verify_headers(url):
    print(f"[*] Auditing Target Headers: {url}")
    print("[*] Environment: Authorized Localhost Lab")
    print()

    try:
        response = requests.get(url, timeout=5)

        print(f"[*] HTTP Status: {response.status_code}")
        print()

        for header in SECURITY_HEADERS:
            if header in response.headers:
                value = response.headers[header]
                print(f"[+] CONFIGURED: {header} -> {value}")
            else:
                print(f"[-] MISSING: {header}")

        print()
        print("[*] Header audit completed.")

    except requests.RequestException as error:
        print(f"[!] Target Unreachable: {error}")


if __name__ == "__main__":
    verify_headers(TARGET_URL)
