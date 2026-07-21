import requests

headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/138.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://codepen.io/",
    "Upgrade-Insecure-Requests": "1"
}

username = "sdhbvsdvbsd"  # Change this later to test an invalid username

url = f"https://codepen.io/{username}"

r = requests.get(
    url,
    headers=headers,
    allow_redirects=True,
    timeout=10
)

print("Status Code:", r.status_code)
print("Final URL:", r.url)
print("Response Length:", len(r.text))
print("\nFirst 500 characters:\n")
print(r.text[:500])