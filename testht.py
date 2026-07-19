import requests

url = "https://www.codechef.com/users/tourist"

r = requests.get(
    url,
    headers={
        "User-Agent": "Mozilla/5.0"
    }
)

print(r.status_code)
print(r.text[:500])