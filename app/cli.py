"""Command-line interface for TraceLens investigations."""

import argparse
from contextlib import redirect_stdout
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any

from app import __version__

SUPPORTED_TYPES = (
    "username", "email", "domain", "ip", "phone", "hash", "md5", "sha1",
    "sha224", "sha256", "sha384", "sha512", "bcrypt", "argon2",
)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INVALID = 2
EXIT_PARTIAL = 3

SHORTCUT_TYPES = {
    "-u": "username", "--username": "username",
    "-e": "email", "--email": "email",
    "-d": "domain", "--domain": "domain",
    "-i": "ip", "--ip": "ip",
    "-p": "phone", "--phone": "phone",
    "-h": "hash", "-x": "hash", "--hash": "hash",
}


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number of seconds") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracelens",
        description="Investigate usernames, email addresses, phone numbers, domains, IPs, and hashes.",
        add_help=False,
    )
    parser.add_argument("--help", action="help", help="show this help message and exit")
    parser.add_argument("--version", action="version", version=f"TraceLens {__version__}")
    parser.add_argument("-H", "--full-help", action="store_true", help="show help for all commands and target shortcuts")
    commands = parser.add_subparsers(dest="command", required=False)
    run = commands.add_parser("investigate", help="run an investigation", add_help=False)
    run.add_argument("--help", action="help", help="show this help message and exit")
    run.add_argument("target", help="target value to investigate")
    run.add_argument(
        "--type",
        choices=SUPPORTED_TYPES,
        help="force a target type instead of detecting it automatically",
    )
    run.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    run.add_argument("--timeout", type=_positive_float, metavar="SECONDS", help="override supported collector network timeouts")
    run.add_argument("--output", "-o", metavar="FILE", help="write the result to a file")
    run.add_argument(
        "--show-plaintext",
        action="store_true",
        help="include plaintext recovered by hash lookups in output",
    )
    run.add_argument("--quiet", "-q", action="store_true", help="disable the elapsed-time indicator")
    return parser


def _investigation_help(parser: argparse.ArgumentParser) -> str:
    action = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    run_parser = action.choices["investigate"]
    shortcuts = (
        "Target shortcuts (tracelens FLAG TARGET):\n"
        "  -u, --username  Username investigation\n"
        "  -e, --email     Email investigation\n"
        "  -d, --domain    Domain investigation\n"
        "  -i, --ip        IP address investigation\n"
        "  -p, --phone     Phone investigation\n"
        "  -h, -x, --hash  Hash identification and lookup (algorithm auto-detected)\n"
    )
    return parser.format_help() + "\n" + shortcuts + "\nInvestigate command options:\n" + run_parser.format_help()


def _normalize_argv(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    target_type = SHORTCUT_TYPES.get(argv[0])
    if target_type is None:
        return argv
    if len(argv) < 2:
        return ["investigate", "--type", target_type]
    return ["investigate", argv[1], "--type", target_type, *argv[2:]]


def _redact(value: Any, include_sensitive: bool) -> Any:
    if isinstance(value, dict):
        return {
            key: ("[redacted]" if key.lower() == "plaintext" and not include_sensitive else _redact(item, include_sensitive))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, include_sensitive) for item in value]
    if isinstance(value, tuple):
        return [_redact(item, include_sensitive) for item in value]
    return value


def _display_scalar(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _append_labeled_value(lines: list[str], label: str, value: Any, indent: int = 0) -> None:
    """Append JSON-like fields with one property per line."""
    prefix = " " * indent
    if isinstance(value, dict):
        lines.append(f'{prefix}{json.dumps(label) + ": " if label else ""}{{')
        for index, (key, child) in enumerate(value.items()):
            _append_labeled_value(lines, str(key), child, indent + 2)
            if index < len(value) - 1:
                lines[-1] += ","
        lines.append(f"{prefix}}}")
        return
    if isinstance(value, (list, tuple)):
        lines.append(f'{prefix}{json.dumps(label) + ": " if label else ""}[')
        for index, item in enumerate(value):
            if isinstance(item, (dict, list, tuple)):
                _append_labeled_value(lines, "", item, indent + 2)
            else:
                lines.append(f"{' ' * (indent + 2)}{_display_scalar(item)}")
            if index < len(value) - 1:
                lines[-1] += ","
        lines.append(f"{prefix}]")
        return
    lines.append(f'{prefix}{json.dumps(label) + ": " if label else ""}{_display_scalar(value)}')


def _append_section(lines: list[str], title: str, values: dict[str, Any]) -> None:
    if not values:
        return
    if lines:
        lines.append("=" * 72)
    lines.append(title.upper())
    lines.append("-" * 72)
    _append_labeled_value(lines, title, values)


def _render_text(result: dict[str, Any], include_sensitive: bool) -> str:
    output = _redact(result, include_sensitive)
    title = f"TraceLens — {str(output.get('type') or output.get('candidate') or 'Investigation').title()}"
    lines = [title]
    overview = {
        "target": output.get("target", ""),
        "status": output.get("status") or ("completed" if output.get("success") else "failed"),
    }
    if output.get("investigation_id"):
        overview["run_id"] = output["investigation_id"]
    if output.get("reason"):
        overview["reason"] = output["reason"]
    _append_section(lines, "Overview", overview)

    data = output.get("data")
    if not isinstance(data, dict):
        if output.get("details"):
            _append_section(lines, "Details", {"items": output["details"]})
        return "\n".join(lines)

    _append_section(lines, "Module", {"name": data.get("module", "Unknown")})
    summary = data.get("summary")
    if isinstance(summary, str):
        _append_section(lines, "Summary", {"text": summary})
    elif isinstance(summary, dict):
        _append_section(lines, "Summary", summary)

    details = data.get("details")
    if isinstance(details, dict):
        _append_section(lines, "Details", details)
    elif isinstance(details, list) and details:
        _append_section(lines, "Details", {"items": details})

    identity = data.get("identity_summary")
    if isinstance(identity, dict):
        _append_section(lines, "Identity assessment", identity)

    evidence = data.get("evidence")
    if isinstance(evidence, list) and evidence:
        _append_section(lines, "Evidence", {"items": evidence})

    usernames = data.get("discovered_usernames")
    if isinstance(usernames, list) and usernames:
        _append_section(lines, "Discovered usernames", {"items": usernames})

    profiles = data.get("profiles")
    if isinstance(profiles, list):
        _append_section(lines, "Platform checks", {"profiles": profiles})

    collectors = data.get("results")
    if isinstance(collectors, list):
        _append_section(lines, "Collectors", {"items": collectors})

    lookup = data.get("lookup")
    if isinstance(lookup, dict):
        _append_section(lines, "Hash lookup", lookup)

    artifacts = data.get("artifacts")
    if isinstance(artifacts, list) and artifacts:
        _append_section(lines, "Findings", {"items": artifacts})

    errors = data.get("errors")
    if isinstance(errors, list) and errors:
        _append_section(lines, "Notes", {"items": errors})

    return "\n".join(lines)


def _run_with_progress(
    target: str,
    forced_type: str | None,
    quiet: bool,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    from app.osint.engine import configure_timeout, investigate

    if timeout_seconds is not None:
        configure_timeout(timeout_seconds)

    if quiet or not sys.stderr.isatty():
        with redirect_stdout(sys.stderr):
            return investigate(target, forced_type=forced_type)

    stopped = threading.Event()

    def report_elapsed() -> None:
        started = time.monotonic()
        while not stopped.wait(0.5):
            elapsed = int(time.monotonic() - started)
            print(f"\rInvestigating… {elapsed}s elapsed", end="", file=sys.stderr, flush=True)

    progress = threading.Thread(target=report_elapsed, daemon=True)
    progress.start()
    try:
        with redirect_stdout(sys.stderr):
            return investigate(target, forced_type=forced_type)
    finally:
        stopped.set()
        progress.join()
        print("\rInvestigation finished.              ", file=sys.stderr, flush=True)


def _has_partial_findings(value: Any) -> bool:
    partial_statuses = {
        "error", "failed", "partial", "source_unavailable", "rate_limited",
        "timeout", "unavailable", "unknown", "unsupported", "placeholder",
    }
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() == "status" and isinstance(item, str) and item.strip().lower().replace(" ", "_") in partial_statuses:
                return True
            if _has_partial_findings(item):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_has_partial_findings(item) for item in value)
    return False


def _exit_code(result: dict[str, Any]) -> int:
    if not result.get("success"):
        if result.get("error_type"):
            return EXIT_ERROR
        data = result.get("data") or {}
        if not isinstance(data, dict):
            data = {}
        reason = str(data.get("error", result.get("reason", ""))).lower()
        details = " ".join(str(item) for item in data.get("details", [])) if isinstance(data.get("details"), list) else str(data.get("details", ""))
        validation_text = f"{reason} {details}".lower()
        if (
            "data" not in result
            or data.get("valid") is False
            or data.get("status") == "invalid"
            or any(marker in validation_text for marker in ("invalid", "syntax", "must contain", "cannot be empty", "structural validation"))
        ):
            return EXIT_INVALID
        return EXIT_ERROR
    return EXIT_PARTIAL if _has_partial_findings(result.get("data", {})) else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    if "-H" in raw_argv or "--full-help" in raw_argv:
        print(_investigation_help(parser), end="")
        return EXIT_OK
    args = parser.parse_args(_normalize_argv(raw_argv))
    if args.command is None:
        parser.print_help()
        return EXIT_INVALID
    try:
        from app.config import load_user_config

        load_user_config()
        result = _run_with_progress(args.target, args.type, args.quiet, args.timeout)
    except KeyboardInterrupt:
        print("\nInvestigation interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        result = {"success": False, "target": args.target, "reason": f"Investigation failed: {exc}", "error_type": "runtime"}

    code = _exit_code(result)
    if args.format == "json":
        rendered = json.dumps(_redact(result, args.show_plaintext), indent=2, ensure_ascii=False, default=str)
    else:
        rendered = _render_text(result, args.show_plaintext)

    if args.output:
        try:
            destination = Path(args.output).expanduser()
            destination.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Could not write output file: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"Results written to {destination}", file=sys.stderr)
    elif args.format == "json":
        print(rendered)
    else:
        stream = sys.stdout
        try:
            print(rendered, file=stream)
        except UnicodeEncodeError:
            sys.stdout.buffer.write((rendered + "\n").encode("utf-8", errors="replace"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
