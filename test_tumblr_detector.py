"""
Test Tumblr Detector with Playwright Anti-Bot Challenge Handling
"""
import sys
from app.osint.data.username_sites import SITES
from app.osint.transport.browser_transport import BrowserTransport
from app.osint.detectors.tumblr import detect as tumblr_detect
from app.osint.modules.username import run_detector

def main():
    tumblr_site = next((s for s in SITES if s["name"] == "Tumblr"), None)
    if not tumblr_site:
        print("ERROR: Tumblr site entry not found in SITES!")
        sys.exit(1)

    print("Found Tumblr Site Config:", tumblr_site)

    transport = BrowserTransport()

    try:
        targets = [
            ("staff", "EXPECTED: FOUND"),
            ("thisuserdoesnotexist123456789987654", "EXPECTED: NOT_FOUND"),
        ]

        for username, exp in targets:
            print("\n" + "=" * 60)
            print(f"Testing username: {username} ({exp})")
            print("=" * 60)

            result = run_detector(tumblr_site, username)
            print("\nResult Dict:")
            for k, v in result.items():
                print(f"  {k}: {v}")

    finally:
        transport.close()

if __name__ == "__main__":
    main()
