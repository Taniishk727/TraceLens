from playwright.sync_api import sync_playwright
import time

VALID_USER = "leetcode"
INVALID_USER = "traceLensDefinitelyInvalid123456"

USERS = [
    ("VALID", VALID_USER),
    ("INVALID", INVALID_USER),
]

def test(username_type, username):
    url = f"https://leetcode.com/u/{username}/"

    print("\n" + "=" * 80)
    print(f"{username_type}: {username}")
    print("=" * 80)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=False,
            slow_mo=100
        )

        context = browser.new_context()
        page = context.new_page()

        requests = []

        def log_request(req):
            requests.append(req.url)

        page.on("request", log_request)

        try:
            response = page.goto(
                url,
                wait_until="networkidle",
                timeout=60000
            )

            print(f"\nInitial URL : {url}")
            print(f"Final URL   : {page.url}")
            print(f"Status Code : {response.status if response else 'None'}")

            # Give Cloudflare time if needed
            time.sleep(8)

            print("\nTitle:")
            print(page.title())

            html = page.content()

            print("\nHTML Length:", len(html))

            markers = [
                "user not found",
                "404",
                "profile",
                "__NEXT_DATA__",
                "graphql",
                username.lower(),
            ]

            print("\nMarker Check")
            print("-" * 40)

            for marker in markers:
                print(f"{marker:20} : {marker.lower() in html.lower()}")

            print("\nDetected GraphQL/API Requests")
            print("-" * 40)

            found = False
            for req in requests:
                if any(x in req.lower() for x in [
                    "graphql",
                    "api",
                    "profile",
                    "user"
                ]):
                    print(req)
                    found = True

            if not found:
                print("No obvious GraphQL/API requests detected.")

            with open(f"leetcode_{username_type.lower()}.html", "w", encoding="utf-8") as f:
                f.write(html)

            page.screenshot(path=f"leetcode_{username_type.lower()}.png", full_page=True)

            print("\nSaved:")
            print(f"  leetcode_{username_type.lower()}.html")
            print(f"  leetcode_{username_type.lower()}.png")

            input("\nInspect the page, then press ENTER...")

        except Exception as e:
            print("\nERROR:", e)

        browser.close()


for typ, user in USERS:
    test(typ, user)