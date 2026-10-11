from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import __version__
from .breach import BreachChecker
from .strength import LABELS, Strength, evaluate, generate
from .term import paint

SCORE_STYLE = ("red", "red", "yellow", "green", "green")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwaudit",
        description="Password audit: strength estimation and breach lookup via k-anonymity.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-f", "--file", type=Path, help="audit a list of passwords, one per line")
    mode.add_argument("-g", "--generate", type=int, nargs="?", const=20, metavar="LENGTH",
                      help="generate a strong password (default length 20)")
    parser.add_argument("--offline", action="store_true", help="skip the breach lookup")
    parser.add_argument("--min-score", type=int, choices=range(5), default=3, metavar="0-4",
                        help="lowest acceptable score for --file (default 3: strong)")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def bar(strength: Strength) -> str:
    filled = (strength.score + 1) * 2
    return paint("#" * filled, SCORE_STYLE[strength.score]) + paint("-" * (10 - filled), "gray")


def mask(password: str) -> str:
    return password[:1] + "*" * (len(password) - 1)


def lookup(checker: BreachChecker | None, password: str) -> int | None:
    if checker is None:
        return None
    try:
        return checker.count(password)
    except OSError as err:
        print(paint(f"  [!] breach lookup unavailable: {getattr(err, 'reason', err)}", "yellow"), file=sys.stderr)
        return None


def describe_breaches(count: int | None) -> str:
    if count is None:
        return paint("not checked", "gray")
    if count:
        return paint(f"found in {count:,} leaks".replace(",", " "), "red", "bold")
    return paint("not found in known leaks", "green")


def show(password: str, checker: BreachChecker | None) -> None:
    strength = evaluate(password)
    label = paint(strength.label, SCORE_STYLE[strength.score], "bold")
    print(f"\n  strength  [{bar(strength)}]  {label}  {paint(f'~{strength.entropy} bits', 'gray')}")
    print(f"  breaches  {describe_breaches(lookup(checker, password))}")
    for warning in strength.warnings:
        print(f"  {paint('[!]', 'yellow')} {warning}")
    print()


def interactive(checker: BreachChecker | None) -> int:
    print(paint("  pwaudit - passwords are never stored or sent in clear text. empty line to quit.", "gray"))
    while True:
        try:
            password = getpass.getpass("  password: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not password:
            return 0
        show(password, checker)


def audit_file(path: Path, checker: BreachChecker | None, min_score: int) -> int:
    try:
        passwords = [line.rstrip("\r\n") for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]
    except OSError as err:
        print(paint(f"[x] {path}: {err.strerror}", "red"), file=sys.stderr)
        return 1
    passwords = [p for p in passwords if p]

    width = min(24, max((len(p) for p in passwords), default=8)) + 2
    print(paint(f"\n  {'#':>4}  {'password':<{width}}{'strength':<14}{'leaks':>12}  notes", "gray"))
    weak = breached = 0
    for index, password in enumerate(passwords, 1):
        strength = evaluate(password)
        leaks = lookup(checker, password)
        weak += strength.score < min_score
        breached += bool(leaks)
        leaks_text = "-" if leaks is None else f"{leaks:,}".replace(",", " ")
        print(
            f"  {index:>4}  {mask(password)[:width - 2]:<{width}}"
            f"{paint(f'{strength.label:<14}', SCORE_STYLE[strength.score])}"
            f"{paint(f'{leaks_text:>12}', 'red' if leaks else 'gray')}  "
            f"{paint(', '.join(strength.warnings), 'gray')}".rstrip()
        )

    print(f"\n  total {len(passwords)}   "
          f"{paint(f'below {LABELS[min_score]}: {weak}', 'red' if weak else 'green')}   "
          f"{paint(f'breached: {breached}', 'red' if breached else 'green')}\n")
    return 1 if weak or breached else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.generate is not None:
        try:
            password = generate(args.generate)
        except ValueError as err:
            print(paint(f"[x] {err}", "red"), file=sys.stderr)
            return 1
        print(password)
        return 0

    checker = None if args.offline else BreachChecker()
    if args.file:
        return audit_file(args.file, checker, args.min_score)
    return interactive(checker)
