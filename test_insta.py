from playwright.sync_api import sync_playwright, TimeoutError
import os
import re

USERNAME = "gavdcdcvs"          # Change to any username
HEADLESS = False

URL = f"https://www.instagram.com/{USERNAME}/"

os.makedirs("instagram_test", exist_ok=True)


def save(page, name):
    page.screenshot(path=f"instagram_test/{name}.png", full_page=True)

    with open(f"instagram_test/{name}.html", "w", encoding="utf-8") as f:
        f.write(page.content())

    print(f"[+] Saved {name}")


def detect_profile(html):
    markers = [
        '"ProfilePage"',
        '"@type":"ProfilePage"',
        '"alternateName"',
        'og:type',
        'profile',
    ]

    found = []

    for marker in markers:
        if marker.lower() in html.lower():
            found.append(marker)

    return found


with sync_playwright() as p:

    browser = p.chromium.launch(
        headless=HEADLESS,
        slow_mo=400
    )

    context = browser.new_context(
        viewport={"width": 1400, "height": 1000},
        locale="en-US"
    )

    page = context.new_page()

    print(f"Opening {URL}")

    page.goto(URL, wait_until="networkidle")

    page.wait_for_timeout(3000)

    print("\n========== INITIAL ==========")
    print("Title :", page.title())
    print("URL   :", page.url)

    save(page, "01_before_close")

    ####################################################################
    # Try multiple methods to dismiss login popup
    ####################################################################

    closed = False

    selectors = [

        "button[aria-label='Close']",
        "svg[aria-label='Close']",
        "div[role='dialog'] button",

        "button:has-text('Not Now')",
        "button:has-text('Cancel')",
        "button:has-text('Close')",

    ]

    for selector in selectors:

        try:
            locator = page.locator(selector).first

            if locator.count() > 0:
                print(f"Trying selector: {selector}")

                locator.click(timeout=3000)

                page.wait_for_timeout(2000)

                closed = True
                print("Popup dismissed.")
                break

        except Exception:
            pass

    ####################################################################
    # Escape key
    ####################################################################

    if not closed:

        try:
            print("Trying Escape key...")

            page.keyboard.press("Escape")

            page.wait_for_timeout(2000)

            closed = True

        except Exception:
            pass

    ####################################################################
    # Click outside dialog
    ####################################################################

    if not closed:

        try:

            print("Trying click outside popup...")

            page.mouse.click(30, 30)

            page.wait_for_timeout(2000)

            closed = True

        except Exception:
            pass

    ####################################################################
    # Remove dialog using JS (debug only)
    ####################################################################

    if not closed:

        try:

            print("Removing dialog using JavaScript...")

            page.evaluate("""
                document.querySelectorAll('[role="dialog"]').forEach(e => e.remove());

                document.body.style.overflow='auto';
            """)

            page.wait_for_timeout(1000)

        except Exception:
            pass

    save(page, "02_after_close")

    html = page.content()

    print("\n========== ANALYSIS ==========")

    markers = detect_profile(html)

    print("Markers found:")

    if markers:
        for m in markers:
            print("  ", m)
    else:
        print("None")

    if "Sorry, this page isn't available" in html:
        print("\nDetected NOT FOUND page")

    meta = re.findall(
        r'<meta property="og:description" content="(.*?)"',
        html,
        re.IGNORECASE,
    )

    if meta:
        print("\nOG Description:")
        print(meta[0])

    print("\nHTML Length:", len(html))

    browser.close()