"""
Test TryHackMe Detector
"""
import sys
from app.osint.data.username_sites import SITES
from app.osint.transport.browser_transport import BrowserTransport
from app.osint.modules.username import run_detector

def main():
    thm_site = next((s for s in SITES if s["name"] == "TryHackMe"), None)
    if not thm_site:
        print("ERROR: TryHackMe site entry not found!")
        sys.exit(1)

    print("TryHackMe Site Config:", thm_site)

    transport = BrowserTransport()

    try:
        targets = [
            ("ben", "EXPECTED: FOUND"),
            ("thisuserdoesnotexist123456789987654", "EXPECTED: NOT_FOUND"),
        ]

        for username, exp in targets:
            print("\n" + "=" * 60)
            print(f"Testing username: {username} ({exp})")
            print("=" * 60)

            result = run_detector(thm_site, username)
            print("\nResult Dict:")
            for k, v in result.items():
                print(f"  {k}: {v}")

    finally:
        transport.close()

if __name__ == "__main__":
    main()
