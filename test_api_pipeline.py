"""
Step 7 - Verify Threads, GitLab, Bitbucket detectors
"""
from app.osint.detectors.redirect import detect as redirect_detect
from app.osint.detectors.api import detect as api_detect
from app.osint.data.username_sites import SITES
from app.osint.transport.requests_transport import RequestsTransport
from app.osint.transport.browser_transport import BrowserTransport

requests_transport = RequestsTransport()
browser_transport = BrowserTransport()

TARGETS = ('Threads', 'GitLab', 'Bitbucket')
USERNAMES = [
    ('zuck', 'EXPECTED: FOUND'),
    ('thisuserdoesnotexist123456789987654', 'EXPECTED: NOT_FOUND'),
]

print('=' * 60)
print('STEP 7 - Threads / GitLab / Bitbucket Verification')
print('=' * 60)

for site in SITES:
    name = site.get('name')
    if name not in TARGETS:
        continue

    detector_name = site.get('detector')
    transport_name = site.get('transport', 'requests')
    transport = browser_transport if transport_name == 'browser' else requests_transport

    print('\nSite       :', name)
    print('Detector   :', detector_name)
    print('Transport  :', transport_name)

    for username, expected in USERNAMES:
        if detector_name == 'redirect':
            result = redirect_detect(site, username, transport)
        else:
            result = api_detect(site, username, transport)

        status       = result.get('status')
        status_code  = result.get('status_code')
        confidence   = result.get('confidence')
        final_url    = result.get('final_url', '')

        print('  [' + expected + ']')
        print('    Username   :', username)
        print('    Status     :', status)
        print('    HTTP code  :', status_code)
        print('    Confidence :', confidence)
        if final_url:
            print('    Final URL  :', final_url)

browser_transport.close()
