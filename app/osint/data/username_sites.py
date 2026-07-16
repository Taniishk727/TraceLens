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
    "category": "Developer",
    "url": "https://bitbucket.org/{}/",
    "detector": "status",
    "expected": 200,
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

{
    "name": "CodePen",
    "category": "Developer",
    "url": "https://codepen.io/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

{
    "name": "Replit",
    "category": "Developer",
    "url": "https://replit.com/@{}",
    "detector": "html",
    "found": [],
    "not_found": [],
    "timeout": 5
},

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
    "redirect_not_found": [
        "/i/flow/login",
        "/search"
    ],
    "timeout": 5
},

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

{
    "name": "Facebook",
    "category": "Social",
    "url": "https://www.facebook.com/{}",
    "detector": "redirect",
    "redirect_not_found": [
        "/login",
        "/recover",
        "/search"
    ],
    "timeout": 5
},

{
    "name": "LinkedIn",
    "category": "Social",
    "url": "https://www.linkedin.com/in/{}",
    "detector": "redirect",
    "redirect_not_found": [
        "/authwall",
        "/login",
        "/checkpoint"
    ],
    "timeout": 5
},

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
    "detector": "html",
    "found": [],
    "not_found": [],
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

    {
        "name": "TryHackMe",
        "category": "Security",
        "url": "https://tryhackme.com/p/{}",
        "detector": "status",
        "expected": 200,
        "timeout": 5
    },

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

{
    "name": "LeetCode",
    "category": "Competitive Programming",
    "url": "https://leetcode.com/u/{}/",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

{
    "name": "HackerRank",
    "category": "Competitive Programming",
    "url": "https://www.hackerrank.com/profile/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5
},

{
    "name": "CodeChef",
    "category": "Competitive Programming",
    "url": "https://www.codechef.com/users/{}",
    "detector": "html",
    "found": [],
    "not_found": [],
    "timeout": 5
},

{
    "name": "Codeforces",
    "category": "Competitive Programming",
    "url": "https://codeforces.com/profile/{}",
    "detector": "html",
    "found": [],
    "not_found": [],
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
    "detector": "html",
    "timeout": 5,
    "found": [],
"not_found": []
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
    "detector": "html",
    "timeout": 5,
    "found": [],
"not_found": [],
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
    "timeout": 5,
    "found": [],
"not_found": []
},

{
    "name": "Crates.io",
    "category": "Open Source",
    "url": "https://crates.io/users/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5,
    "found": [],
"not_found": []
},

{
    "name": "Packagist",
    "category": "Open Source",
    "url": "https://packagist.org/users/{}",
    "detector": "status",
    "expected": 200,
    "timeout": 5,
    "found": [],
"not_found": []
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