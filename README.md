# TraceLens

TraceLens runs OSINT investigations through both a Linux command-line interface and a Flask web interface. Both interfaces call the same investigation dispatcher and target-specific engines.

## Install from GitHub on Linux

TraceLens supports Linux systems with Python 3.10 or newer. On Debian or Ubuntu, install Git, Python, and `pipx` first:

```sh
sudo apt update
sudo apt install -y git python3 python3-venv pipx
pipx ensurepath
```

Open a new terminal after `pipx ensurepath` if the `pipx` command is not found. Install TraceLens directly from GitHub with [pipx](https://pipx.pypa.io/):

```sh
pipx install "git+https://github.com/Taniishk727/TraceLens.git"
tracelens --help
```

Start the CLI with `tracelens`. To use the web interface, run `tracelens-web`; it is installed alongside the CLI. To download the source and install from a local checkout instead:

```sh
git clone https://github.com/Taniishk727/TraceLens.git
cd TraceLens
pipx install .
```

To update a GitHub installation later, run `pipx upgrade tracelens-osint`. For development, clone the repository, create a virtual environment, and run `python -m pip install -e ".[dev]"` from the repository directory.

## CLI usage

```sh
tracelens -H
tracelens -u torvalds
tracelens -e user@example.com --format json
tracelens -d example.com
tracelens -i 203.0.113.10
tracelens -p +14155552671
tracelens -x HASH_VALUE
tracelens --hash HASH_VALUE --show-plaintext
tracelens investigate torvalds
tracelens investigate user@example.com --format json
tracelens investigate 203.0.113.10 --type ip --output result.json --format json
tracelens investigate HASH_VALUE --type hash --show-plaintext
tracelens investigate torvalds --timeout 5
```

`-H` shows the full help, including all investigation options and shortcuts. Target shortcuts are `-u`/`--username`, `-e`/`--email`, `-d`/`--domain`, `-i`/`--ip`, `-p`/`--phone`, and `-x`/`--hash`. The existing `tracelens investigate TARGET` command remains supported. Without a target shortcut or `--type`, TraceLens attempts to identify the target type. Output is text by default; JSON is available for scripts. Hash lookup plaintext is redacted unless `--show-plaintext` is supplied. Exit codes are `0` for complete results, `1` for an investigation/configuration failure, `2` for invalid input or usage, `3` when results contain partial or unavailable sources, and `130` when interrupted.

Username scans may take time. In an interactive terminal, progress is written to stderr so JSON on stdout remains usable in pipelines.
`--timeout` overrides supported network collector timeouts in seconds; system DNS resolver calls may use their own timeout.

## Web interface

The Flask interface remains available from the same installation with `tracelens-web` (it binds to localhost by default). From a source checkout, you can also run:

```sh
python run.py
```

For browser-based username checks, install the optional browser dependency in a virtual environment and install Chromium:

```sh
python -m pip install -e ".[browser]"
python -m playwright install chromium
```

Without Playwright and Chromium, browser-backed checks are reported unavailable; other checks continue. Do not expose Flask's development server directly to an untrusted network.

## Configuration

Environment variables take precedence over the user config file. TraceLens reads `HIBP_API_KEY` and the optional `VIRUSTOTAL_API_KEY` from the environment or from `config.json` at:

- Linux: `$XDG_CONFIG_HOME/tracelens/config.json`, or `~/.config/tracelens/config.json` if `XDG_CONFIG_HOME` is unset.
- Windows: `%APPDATA%\tracelens\config.json`.

Set `TRACELENS_CONFIG` to use a different config path. Example:

```json
{
  "HIBP_API_KEY": "your-api-key",
  "VIRUSTOTAL_API_KEY": "your-api-key"
}
```

Hash lookups include the keyless CIRCL hashlookup catalog (MD5, SHA-1, SHA-256). A match gives known-file metadata, not plaintext and not a safety verdict. Add `VIRUSTOTAL_API_KEY` to enable VirusTotal file reports; its public API is limited to four requests per minute and intended for non-commercial or academic use. VirusTotal says queried indicators are added to its community dataset, so avoid querying sensitive or confidential indicators. Hash lookups send the queried hash to public services. Keep the config file private because it may contain API credentials.

## Current capabilities and limitations

- **Usernames:** Concurrent public profile and API checks against the registered platform list. Browser-backed checks are optional.
- **Email:** Provider/domain metadata, verification, account and identity signals, public search, reputation, avatars, PGP, Git profile, and breach lookups. Some providers need credentials or may be unavailable.
- **Phone:** Parsing, number type, carrier metadata, public search, and risk/reputation signals.
- **Hashes:** Format/algorithm identification, public plaintext lookup, known-file catalog lookup, and optional VirusTotal report lookup. Plaintext recovery is never guaranteed.
- **Domains:** Validated IDNA domain input and bounded DNS lookups for A, AAAA, MX, NS, TXT, CAA, and SOA records, plus SPF and DMARC checks.
- **IP addresses:** IPv4/IPv6 classification, reverse DNS, and optional keyless geolocation, network, and ASN enrichment for globally routable addresses.

Results depend on local DNS and external services. An unavailable source does not mean the target has no public information. Investigations currently run synchronously. Persistent cases, an interactive graph canvas, and report downloads are not implemented.

## Project layout

- `app/osint/`: Shared dispatcher, target engines, collectors, and transports.
- `app/cli.py`: CLI interface (`tracelens`).
- `app/routes.py`, `app/templates/`, `app/static/`: Flask web interface.
- `run.py`: Web development-server entry point.
- `tests/`: Existing tests.
