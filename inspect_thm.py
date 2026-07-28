"""
Inspect TryHackMe profile page HTML for real usernames
"""
from playwright.sync_api import sync_playwright

USERNAMES = ["ben", "skynet", "thm", "TryHackMe"]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    for user in USERNAMES:
        url = f"https://tryhackme.com/p/{user}"
        page.goto(url, wait_until="domcontentloaded")
        page.wait_for_timeout(4000)
        print("=" * 60)
        print("URL:", page.url)
        print("Title:", page.title())
        html = page.content()
        og_image = ""
        loc = page.locator("meta[property='og:image']")
        if loc.count() > 0:
            og_image = loc.first.get_attribute("content")
        print("og:image:", og_image)
        print("Contains 'user-avatars':", "user-avatars" in html)
        print("Contains 'user-avatar':", "user-avatar" in html)
        print("Avatar imgs:", [img.get_attribute("src") for img in page.locator("img").all() if img.get_attribute("src") and "avatar" in img.get_attribute("src").lower()])
    browser.close()
