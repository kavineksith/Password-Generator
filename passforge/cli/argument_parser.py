"""Argparse definitions for scripted/automation CLI usage."""

from __future__ import annotations

import argparse

from passforge import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passforge",
        description="Industrial-grade asynchronous password and passphrase generator.",
    )
    parser.add_argument("--version", action="version", version=f"passforge {__version__}")
    parser.add_argument(
        "--length", type=int, required=True, help="Password length, or word count for passphrases"
    )
    parser.add_argument(
        "--category",
        choices=["alphanumeric", "complex", "passphrase"],
        required=True,
        help="Password category to generate",
    )
    parser.add_argument(
        "--strength",
        choices=["basic", "strong", "paranoid"],
        default="strong",
        help="Password strength/security tier (default: strong)",
    )
    parser.add_argument("--count", type=int, default=1, help="Number of passwords to generate (default: 1)")
    parser.add_argument("--output", help="Path to save results (.json or .csv)")
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=16,
        help="Max concurrent generation workers for bulk requests (default: 16)",
    )
    parser.add_argument(
        "--wordlist",
        default="eff_large_wordlist.txt",
        help="Path to EFF wordlist file for passphrase generation",
    )
    parser.add_argument(
        "--exclude-chars", default="", help="Characters to exclude from generation"
    )
    parser.add_argument(
        "--no-exclude-similar",
        action="store_true",
        help="Do not exclude visually similar characters (l, 1, I, o, O, 0)",
    )
    parser.add_argument(
        "--log-dir", default="logs", help="Directory for the accountability audit log (default: logs)"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress console logging (audit log still written)"
    )
    return parser
