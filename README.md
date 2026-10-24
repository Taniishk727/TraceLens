# TraceLens

TraceLens is an OSINT investigation app with a Flask web interface. Its investigation engines are organized by target type so they can also be reused by another interface.

## Current capabilities

- **Usernames:** Concurrent checks against registered public platform profile pages and APIs.
- **Email addresses:** Syntax and provider metadata, DNS/domain checks, public account and identity signals, breach lookups, and reputation findings. Some providers require API keys or may be unavailable.
- **Phone numbers:** Parsing and normalization, number classification, carrier metadata, public search, and risk/reputation signals.
- **Hashes:** Format and algorithm identification plus public hash database lookups.
- **Domains:** System DNS resolution to IPv4 and IPv6 addresses.
- **IP addresses:** IPv4/IPv6 classification and reverse DNS lookup.

Findings depend on the local resolver and external services. An unavailable source does not mean a target has no public information.

## Current limitations

- Investigations run synchronously in the web request.
- Case storage, a persistent evidence store, interactive graph canvas, and report downloads are not implemented.
- Browser-based username checks require Playwright and a compatible Chromium installation. Without them, those checks are reported as unavailable while other checks continue.
- Breach-provider coverage depends on API configuration; set `HIBP_API_KEY` to use Have I Been Pwned.

## Run the web app

```sh
python -m pip install -r requirements.txt
python run.py
```

The app listens on Flask's local development address. Do not expose the development server directly to an untrusted network.

To enable browser-backed username checks, install Playwright separately and run `python -m playwright install chromium`.

## Layout

- `app/routes.py` and `app/templates/`: Flask routes and pages.
- `app/osint/engine.py`: Target detection and engine dispatch.
- `app/osint/modules/`: Username, email, phone, and hash engines and collectors.
- `app/osint/parsers/`: Domain, IP, and hash investigation entry points.
- `app/osint/core/transport/`: Shared HTTP and optional browser transports.
- `tests/`: Existing unit and route tests.

## Dependencies

The project currently uses Python, Flask, Requests, and `phonenumbers`. SQLAlchemy packages remain in `requirements.txt`, but the app does not currently persist investigations with a database.
