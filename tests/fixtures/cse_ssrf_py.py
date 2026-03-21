"""CWE-918: Server-Side Request Forgery (SSRF) in Python
Fetches URLs constructed from user input without validation."""

import sys
try:
    from urllib.request import urlopen
    from urllib.parse import urljoin
except ImportError:
    pass


API_BASE = "http://internal-api:8080"


def fetch_url(user_url):
    """SSRF: directly opens user-supplied URL."""
    response = urlopen(user_url)
    return response.read().decode()


def proxy_request(target_host, path):
    """SSRF: constructs internal URL from user input."""
    url = f"http://{target_host}/{path}"
    response = urlopen(url)
    return response.read()


def get_avatar(user_id, avatar_url):
    """SSRF: fetches user-supplied avatar URL from server side."""
    response = urlopen(avatar_url)
    data = response.read()
    with open(f"/tmp/avatars/{user_id}.png", "wb") as f:
        f.write(data)
    return len(data)


def webhook_notify(callback_url, payload):
    """SSRF: posts to user-supplied callback URL."""
    import urllib.request
    req = urllib.request.Request(callback_url, data=payload.encode(),
                                headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(req).read()


def main():
    if len(sys.argv) < 2:
        return
    content = fetch_url(sys.argv[1])
    print(content[:200])


if __name__ == "__main__":
    main()
