"""Command-line launcher for the Flask interface."""

import argparse

from app import create_app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tracelens-web", description="Run the TraceLens web interface.")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=5000, help="port to listen on")
    args = parser.parse_args(argv)
    create_app().run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
