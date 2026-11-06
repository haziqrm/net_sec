"""Entry point: ``python -m playground.shell [--defence]``."""

from __future__ import annotations

import argparse
from typing import List, Optional

from playground.shell.cli import banner, build_session, repl


def main(argv: Optional[List[str]] = None) -> None:
    """Parse the command line and start the shell."""
    parser = argparse.ArgumentParser(
        prog="python -m playground.shell",
        description="Play the attacker on a simulated LAN. Nothing touches your real network.",
    )
    parser.add_argument(
        "--defence",
        action="store_true",
        help="give the victim a static ARP entry for the gateway before you start",
    )
    args = parser.parse_args(argv)
    for line in banner(args.defence):
        print(line)
    repl(build_session(defence=args.defence))


if __name__ == "__main__":
    main()
