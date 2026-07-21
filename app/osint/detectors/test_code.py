from playwright_detector import PlaywrightDetector

browser = PlaywrightDetector()

result = browser.check(
    "https://codepen.io/chriscoyier"
)

print("=" * 50)
print("Status :", result["status"])
print("Title  :", result["title"])
print("URL    :", result["final_url"])
print("Length :", result["length"])
print("Time   :", result["elapsed"])
print("=" * 50)

print(result["graphql"])