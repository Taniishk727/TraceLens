from playwright.sync_api import sync_playwright

USERNAMES = [
    ("VALID", "tryhackme"),
    ("INVALID", "thisuserdoesnotexist123456789"),
]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()

    for label, username in USERNAMES:
        print("\n" + "=" * 60)
        print(label)
        print("=" * 60)

        url = f"https://tryhackme.com/p/{username}"
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_load_state("load")
        page.wait_for_timeout(3000)
        print("Title:", page.title())
        print("URL:", page.url)

        print("\nOG Image:")
        og = page.locator("meta[property='og:image']")
        if og.count():
            print(og.first.get_attribute("content"))

        print("\nImages containing 'user':")
        for img in page.locator("img").evaluate_all(
            "(els) => els.map(e => e.src).filter(s => s.includes('user'))"
        ):
            print(img)

        print("\nMain HTML (first 3000 chars):")
        main = page.locator("main")
        if main.count():
            print(main.first.inner_html()[:3000])

        page.screenshot(path=f"{label.lower()}.png", full_page=True)

    browser.close()