"""
============================================================
TraceLens Site Verification Utility
============================================================

Developer tool for validating username site definitions.

Features
--------
✓ HTTP status code
✓ Redirect detection
✓ Final URL
✓ Page title
✓ Response time
✓ First 500 characters of HTML
✓ Save HTML for inspection

Usage
-----
python -m app.tools.verify_site

Author:
TraceLens
"""

import time
import requests
from bs4 import BeautifulSoup

from app.osint.data.username_sites import SITES
from app.osint.detectors.constants import HEADERS


FAKE_USERNAME = "asdfqwerzxcv9876543"


def verify_site(site):

    url = site["url"].format(FAKE_USERNAME)

    print("=" * 70)
    print(f"Site      : {site['name']}")
    print(f"Category  : {site['category']}")
    print(f"Detector  : {site['detector']}")
    print(f"URL       : {url}")
    print("=" * 70)

    start = time.perf_counter()

    try:

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=site.get("timeout", 5),
            allow_redirects=True
        )

        elapsed = round(
            (time.perf_counter() - start) * 1000,
            2
        )

        print(f"Status Code : {response.status_code}")
        print(f"Final URL   : {response.url}")
        print(f"Redirected  : {response.url != url}")
        print(f"Time        : {elapsed} ms")

        soup = BeautifulSoup(response.text, "html.parser")

        title = soup.title.string.strip() if soup.title else "N/A"

        print(f"Page Title  : {title}")

        print("\nHTML Preview")
        print("-" * 70)

        preview = response.text[:500]

        print(preview)

        print("\n")

        filename = (
            site["name"]
            .lower()
            .replace(" ", "_")
            + ".html"
        )

        with open(filename, "w", encoding="utf-8") as f:
            f.write(response.text)

        print(f"Saved HTML : {filename}")

    except Exception as exc:

        print(f"ERROR : {exc}")

    print()


def main():

    print("\nTraceLens Site Verification Utility\n")

    print("Available Sites\n")

    for index, site in enumerate(SITES, start=1):

        print(f"{index:2}. {site['name']}")

    print()

    choice = int(input("Select Site Number : "))

    print()

    verify_site(SITES[choice - 1])


if __name__ == "__main__":
    main()