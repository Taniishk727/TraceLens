"""
============================================================
TraceLens Username Site Database
============================================================

Each entry represents one supported platform.

Fields
------
name        : Display name
category    : Platform category
url         : Username profile URL
detector    : Detector module to use
expected    : Expected HTTP status (status detector)
timeout     : Request timeout (seconds)
"""

SITES = [

 # ======================================================
# Developer Platforms
# ======================================================

{
    "name": "GitHub",
    "category": "Developer",
    "url": "https://github.com/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

{
    "name": "GitLab",
    "category": "Developer",
    "url": "https://gitlab.com/{}",

    "detector": "api",

    "api_url": "https://gitlab.com/api/v4/users?username={}",

    "api_mode": "non_empty_list",

    "timeout": 5
},

{
    "name": "Bitbucket",
    "url": "https://bitbucket.org/{}/",
    "category": "Developer",
    "detector": "api",
    "api_url": "https://api.bitbucket.org/2.0/workspaces/{}",
    "timeout": 5
},

{
    "name": "SourceForge",
    "category": "Developer",
    "url": "https://sourceforge.net/u/{}/profile/",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

{
    "name": "Launchpad",
    "category": "Developer",
    "url": "https://launchpad.net/~{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},
# TODO: CodePen blocks automated requests (HTTP 403).
# Revisit later with browser headers, cookies, or an alternative API.
{
    "name": "CodePen",
    "category": "Developer",
    "url": "https://codepen.io/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

# TODO: Replit profile pages require authentication.
# Investigate public API or GraphQL endpoint.
{
    "name": "Replit",
    "category": "Developer",
    "url": "https://replit.com/@{}",
    "detector": "html",
    "found": [],
    "not_found": [],
    "timeout": 5
},
# TODO: Migrate Hashnode to GraphQL API.
# Profile pages return HTTP 200 for both existing and non-existing users.
{
    "name": "Hashnode",
    "category": "Developer",
    "url": "https://hashnode.com/@{}",
    "detector": "html",
    "found": [],
    "not_found": [],
    "timeout": 5
},


{
    "name": "Docker Hub",
    "category": "Developer",
    "url": "https://hub.docker.com/u/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5,
    "found": [],
"not_found": []
},

{
    "name": "Hugging Face",
    "category": "Developer",
    "url": "https://huggingface.co/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5,
    "found": [],
"not_found": []
},

# TODO: Migrate Kaggle to API detector.
# Profile pages return HTTP 200 for both existing and non-existing users.
{
    "name": "Kaggle",
    "category": "Developer",
    "url": "https://www.kaggle.com/{}",
    "detector": "html",
    "found": [],
    "not_found": [],
    "timeout": 5,
    "found": [],
"not_found": []
},

{
    "name": "npm",
    "category": "Developer",
    "url": "https://www.npmjs.com/~{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5,
    "found": [],
"not_found": []
},
   # ======================================================
# Social Media
# ======================================================

# TODO: Migrate Reddit from HTML to JSON API.
# HTML layout has changed; current markers are obsolete.
{
    "name": "Reddit",
    "category": "Social",
    "url": "https://www.reddit.com/user/{}",
    "detector": "html",
    "found": [
        "karma"
    ],
    "not_found": [
        "sorry, nobody on reddit goes by that name"
    ],
    "timeout": 5
},

# Needs API / HTML Update
{
    "name": "Instagram",
    "category": "Social",
    "url": "https://www.instagram.com/{}/",
    "detector": "html",
    "found": [
        "followers",
        "following"
    ],
    "not_found": [
        "sorry, this page isn't available"
    ],
    "timeout": 5
},

{
    "name": "X",
    "category": "Social",
    "url": "https://x.com/{}",

    "detector": "redirect",

    # HTTP status codes
    "not_found_status": [
        404
    ],

    "unknown_status": [
        429
    ],

    # Redirect destinations indicating a missing profile
    "redirect_not_found": [
        "/i/flow/login",
        "/search"
    ],

    "timeout": 5
},

# Login req for threads
{
    "name": "Threads",
    "category": "Social",
    "url": "https://www.threads.net/@{}",
    "detector": "html",
    "found": [
        "threads"
    ],
    "not_found": [
        "sorry, this page isn't available"
    ],
    "timeout": 5
},

# TODO: Facebook serves HTTP 400 for public requests.
# Invalid profiles display a client-side "This content isn't available"
# page that is not reliably detectable from raw HTML.
# Revisit with Playwright/browser automation in Phase 2.
{
    "name": "Facebook",
    "category": "Social",
    "url": "https://www.facebook.com/{}",
    "detector": "html",

    "found": [
       "follewers"
    ],

    "not_found": [
        "this content isn't available",
        "this page isn't available",
        "This content isn't available at the moment"
    ],

    "timeout": 5
},
# TODO: LinkedIn aggressively blocks automated requests.
# Well-known/public profiles may return HTTP 200, while many valid profiles
# return HTTP 999 (bot protection), making reliable username verification
# impossible without browser automation or an authenticated session.
# Revisit in Phase 2 with Playwright.
{
    "name": "LinkedIn",
    "category": "Social",
    "url": "https://www.linkedin.com/in/{}",

    "detector": "redirect",

    # LinkedIn blocks bots with 999
    "unknown_status": [
        999
    ],

    # Redirect destinations
    "redirect_not_found": [
        "/authwall",
        "/login",
        "/checkpoint"
    ],

    "timeout": 5
},

# TODO: Pinterest now requires authentication to reliably access profiles.
# Public requests return a generic/login page, preventing reliable username
# verification using HTTP status or HTML inspection.
# Revisit in Phase 2 with browser automation.
{
    "name": "Pinterest",
    "category": "Social",
    "url": "https://www.pinterest.com/{}/",
    "detector": "html",
    "found": [
        "followers"
    ],
    "not_found": [
        "sorry! we couldn't find that page"
    ],
    "timeout": 5
},

# TODO: Tumblr uses browser verification / anti-bot protection.
# Automated requests receive HTTP 403 before reaching the profile page.
# Valid profiles load after browser verification, while invalid profiles
# show "There's nothing here."
# Revisit in Phase 2 with Playwright/browser automation.
{
    "name": "Tumblr",
    "category": "Social",
    "url": "https://{}.tumblr.com",
    "detector": "html",
    "found": [
        "archive"
    ],
    "not_found": [
        "there's nothing here"
    ],
    "timeout": 5
},

{
    "name": "Snapchat",
    "category": "Social",
    "url": "https://www.snapchat.com/add/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},
    # ======================================================
    # Blogging
    # ======================================================

    

    {
        "name": "Dev.to",
        "category": "Blogging",
        "url": "https://dev.to/{}",
        "detector": "status",
        "expected": 200,
        "timeout": 5
    },

    # ======================================================
    # Cybersecurity
    # ======================================================

    {
        "name": "HackerOne",
        "category": "Security",
        "url": "https://hackerone.com/{}",
        "detector": "status",
        "expected": 200,
        "timeout": 5
    },

    {
        "name": "Bugcrowd",
        "category": "Security",
        "url": "https://bugcrowd.com/{}",
        "detector": "status",
        "expected": 200,
        "timeout": 5
    },

# Requires browser automation.
# Automated requests receive HTTP 429 for both existing and non-existing users.
# Profiles and "Page Not Found" pages are only accessible after passing browser checks.
    {
        "name": "TryHackMe",
        "category": "Security",
        "url": "https://tryhackme.com/p/{}",
        "detector": "status",
        "expected": 200,
        "timeout": 5
    },

# Requires authentication.
# Unauthenticated requests are redirected to the sign-in page (HTTP 200).
# Cannot distinguish valid and invalid usernames using status or HTML detection.
# Requires authenticated browser automation or official API.
    {
        "name": "Hack The Box",
        "category": "Security",
        "url": "https://app.hackthebox.com/users/{}",
        "detector": "status",
        "expected": 200,
        "timeout": 5
    },

    # ======================================================
# Competitive Programming
# ======================================================

# Protected by Cloudflare.
# Unauthenticated requests receive HTTP 403 before profile resolution.
# Actual profile or "user not found" page is only available after the browser completes the Cloudflare challenge.
# Requires browser automation (Playwright) or an official API.
{
    "name": "LeetCode",
    "category": "Competitive Programming",
    "url": "https://leetcode.com/u/{}/",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

# Phase 2 Notes:
    # HTML markers are present in both raw HTML and parsed text,
    # but the detector still returns Unknown during concurrent scans.
    # Revisit after Phase 1 completion. May require browser automation
    # or deeper investigation into the detector execution path.
{
    "name": "HackerRank",
    "category": "Coding",
    "url": "https://www.hackerrank.com/profile/{}",
    "detector": "html",
    "found": ["Education","Certifications","Badges"],
    "not_found": [
        "We could not find the page you were looking for"
    ],
    "timeout": 5
},
# PHASE 2:codechef
{
    "name": "CodeChef",
    "category": "Competitive Programming",
    "url": "https://www.codechef.com/users/{}",
    "detector": "html",
    "found": ["Username:","Country:","Organisation:"],
    "not_found": [" The username specified does not exist in our database."],
    "timeout": 5
},

{
    "name": "Codeforces",
    "category": "Competitive Programming",
    "url": "https://codeforces.com/profile/{}",
    "detector": "html",
    "found": ["Contest rating","contribution","problems"],
    "not_found": ["Unofficial participants","Official participants"],
    "timeout": 5
},
{
    "name": "AtCoder",
    "category": "Competitive Programming",
    "url": "https://atcoder.jp/users/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

# # TODO: GeeksforGeeks has changed its profile routing.
# Both existing and non-existing usernames resolve to the same generic page
# with HTTP 200, making reliable detection impossible using status, HTML,
# or redirect-based methods. Revisit in Phase 2 after investigating the
# current profile URL structure or any available API.
{
    "name": "GeeksforGeeks",
    "category": "Competitive Programming",
    "url": "https://auth.geeksforgeeks.org/user/{}/",
    "detector": "html",
    "found": [],
    "not_found": [],
    "timeout": 5
},

# ======================================================
# Design & Portfolio
# ======================================================

# # TODO: Canva public profile URL has changed.
# The legacy /p/{username} route no longer resolves for public profiles.
# Investigate the current Creator profile URL or any public API.
# Revisit in Phase 2.
{
    "name": "Canva",
    "category": "Design",
    "url": "https://www.canva.com/p/{}",
    "detector": "html",
    "timeout": 5,
    "found": [],
"not_found": [],
},

{
    "name": "Figma",
    "category": "Design",
    "url": "https://www.figma.com/@{}",
    "detector": "html",
    "timeout": 5,
    "found": [],
"not_found": []
},

{
    "name": "Product Hunt",
    "category": "Portfolio",
    "url": "https://www.producthunt.com/@{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

{
    "name": "About.me",
    "category": "Portfolio",
    "url": "https://about.me/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5,
    "found": [],
"not_found": []
},

{
    "name": "Linktree",
    "category": "Portfolio",
    "url": "https://linktr.ee/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5,
    "found": [],
"not_found": []
},

{
    "name": "Carrd",
    "category": "Portfolio",
    "url": "https://{}.carrd.co",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

{
    "name": "Buy Me a Coffee",
    "category": "Portfolio",
    "url": "https://buymeacoffee.com/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5,
    "found": [],
"not_found": []
},

# TODO: Ko-fi returns HTTP 200 for both existing and non-existing
# usernames. Investigate HTML markers or redirect behavior in Phase 2.
{
    "name": "Ko-fi",
    "category": "Portfolio",
    "url": "https://ko-fi.com/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5,
    "found": [],
"not_found": []
},

# ======================================================
# Gaming
# ======================================================

# TODO: Steam Community employs anti-bot protection.
# Existing profiles may return HTTP 429 while non-existing profiles
# return HTTP 200 with a generic page. Reliable detection requires
# browser automation or a different approach. Revisit in Phase 2.
{
    "name": "Steam Community",
    "category": "Gaming",
    "url": "https://steamcommunity.com/id/{}",
    "detector": "html",
    "timeout": 5,
    "found": [],
"not_found": []
},



{
    "name": "Chess.com",
    "category": "Gaming",
    "url": "https://www.chess.com/member/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5,
    "found": [],
"not_found": []
},

{
    "name": "Lichess",
    "category": "Gaming",
    "url": "https://lichess.org/@/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5,
    "found": [],
"not_found": []
},
# ======================================================
# Research & Open Source
# ======================================================




{
    "name": "RubyGems",
    "category": "Open Source",
    "url": "https://rubygems.org/profiles/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

{
    "name": "Crates.io",
    "category": "Open Source",
    "url": "https://crates.io/users/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

{
    "name": "Packagist",
    "category": "Open Source",
    "url": "https://packagist.org/users/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},



{
    "name": "ResearchGate",
    "category": "Research",
    "url": "https://www.researchgate.net/profile/{}",
    "detector": "html",
    "timeout": 5,
    "found": [],
"not_found": []
}
]