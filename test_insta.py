#!/usr/bin/env python3

"""
Hack The Box Username Investigation

Checks:
1. Status code
2. Redirect chain
3. Final URL
4. HTML title
5. Meta tags
6. Login markers
7. Profile markers
8. Saves HTML for comparison
"""

import requests
from bs4 import BeautifulSoup

VALID = "0xdf"                     # Replace if needed
INVALID = "this_username_should_not_exist_123456789"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/138.0.0.0 Safari/537.36"
    )
}


def inspect(username):
    url = f"https://app.hackthebox.com/users/{username}"

    print("=" * 80)
    print("USERNAME :", username)
    print("URL      :", url)

    r = requests.get(
        url,
        headers=HEADERS,
        allow_redirects=False,
        timeout=15,
    )

    print("\nWITHOUT REDIRECTS")
    print("-----------------")
    print("Status :", r.status_code)
    print("Location :", r.headers.get("Location"))

    r = requests.get(
        url,
        headers=HEADERS,
        allow_redirects=True,
        timeout=15,
    )

    print("\nFINAL RESPONSE")
    print("--------------")
    print("Status :", r.status_code)
    print("Final URL :", r.url)
    print("Content-Length :", len(r.text))

    filename = f"{username}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(r.text)

    print("Saved HTML ->", filename)

    soup = BeautifulSoup(r.text, "html.parser")

    print("\nTITLE")
    print("-----")
    print(soup.title.string if soup.title else "None")

    print("\nMETA")
    print("----")

    for prop in [
        "og:title",
        "og:description",
        "twitter:title",
        "description",
    ]:
        tag = soup.find("meta", attrs={"property": prop})
        if tag is None:
            tag = soup.find("meta", attrs={"name": prop})

        if tag:
            print(prop, ":", tag.get("content"))

    print("\nCOMMON MARKERS")
    print("--------------")

    markers = [
        "Sign in",
        "Login",
        "Log in",
        "Hack The Box",
        "Profile",
        "User",
        "404",
        "Page not found",
        "Unauthorized",
        "Forbidden",
        "Dashboard",
    ]

    html = r.text.lower()

    for marker in markers:
        print(f"{marker:25} -> {marker.lower() in html}")

    print()


inspect(VALID)
inspect(INVALID)

print("=" * 80)
print("Next steps:")
print("1. Compare valid and invalid HTML.")
print("2. Open DevTools → Network.")
print("3. Look for XHR/Fetch/GraphQL requests.")
print("4. Determine whether a public API exists.")
print("=" * 80)