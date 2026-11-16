import argparse
import json
import os
import subprocess
import sys
from typing import List, Optional, Sequence, Tuple

from . import __version__
from .ignore import load_default_ignore, should_skip_path
from .report import print_report, render_json, supports_color
from .rules import RULES, SEVERITY_RANK
from .scanner import Scanner

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=(
            "Scan files and repositories for leaked secrets and sensitive data "
            "before they leave your machine."
        ),
        epilog=(
            "Examples:\n"
            "  sentinel .                      scan the current directory\n"
            "  sentinel --staged               scan only files staged in git\n"
            "  sentinel src/ --fail-on high    fail CI only on high+ severity\n"
            "  sentinel --json > report.json   machine-readable output\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="*", metavar="PATH", help="files or directories to scan (default: .)")
    parser.add_argument("--staged", action="store_true", help="scan the exact content staged in git's index")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument("--no-entropy", action="store_true", help="disable high-entropy string detection")
    parser.add_argument("--no-pii", action="store_true", help="disable personal data rules (cards, SSNs)")
    parser.add_argument(
        "--max-size",
        type=int,
        default=1_000_000,
        metavar="BYTES",
        help="skip files larger than this (default: 1000000)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="extra ignore pattern, repeatable (gitignore syntax)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "none"),
        default="low",
        help="lowest severity that causes a non-zero exit (default: low)",
    )
    parser.add_argument("--show-secrets", action="store_true", help="do not redact matched values")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--quiet", action="store_true", help="suppress findings output, keep exit code")
    parser.add_argument("--list-rules", action="store_true", help="list detection rules and exit")
    parser.add_argument("--version", action="version", version=f"sentinel {__version__}")
    return parser


def _git(*arguments: str, cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", cwd, *arguments],
        capture_output=True,
        text=True,
    )


def staged_entries(cwd: str) -> Tuple[str, List[Tuple[str, bytes]], List[str]]:
    root_result = _git("rev-parse", "--show-toplevel", cwd=cwd)
    if root_result.returncode != 0:
        raise RuntimeError("not inside a git repository")
    root = root_result.stdout.strip()
    diff_result = subprocess.run(
        [
            "git",
            "-C",
            root,
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
        ],
        capture_output=True,
    )
    if diff_result.returncode != 0:
        message = diff_result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(message or "git diff failed")
    entries: List[Tuple[str, bytes]] = []
    errors: List[str] = []
    for raw in diff_result.stdout.split(b"\x00"):
        if not raw:
            continue
        name = os.fsdecode(raw)
        blob = subprocess.run(
            ["git", "-C", root, "show", ":" + name],
            capture_output=True,
        )
        if blob.returncode != 0:
            errors.append(f"cannot read staged content for {name}")
            continue
        entries.append((name, blob.stdout))
    return root, entries, errors


def _print_rules() -> None:
    rows = [("ID", "SEVERITY", "NAME", "DESCRIPTION")]
    for rule in RULES:
        rows.append((rule.id, rule.severity, rule.name, rule.description))
    widths = [max(len(row[index]) for row in rows) for index in range(4)]
    for row in rows:
        print("  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip())


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        _print_rules()
        return EXIT_CLEAN

    paths = list(args.paths) or ["."]
    scanner_options = dict(
        use_entropy=not args.no_entropy,
        include_pii=not args.no_pii,
        max_size=args.max_size,
    )
    staged_errors: List[str] = []
    try:
        if args.staged:
            try:
                repo_root, entries, staged_errors = staged_entries(os.getcwd())
            except RuntimeError as exc:
                print(f"sentinel: {exc}", file=sys.stderr)
                return EXIT_ERROR
            scanner = Scanner(display_root=repo_root, **scanner_options)
            ignore = load_default_ignore([repo_root, os.getcwd()], excludes=args.exclude)
            sources = [
                (name, data)
                for name, data in entries
                if not should_skip_path(name) and not ignore.ignores_path(name)
            ]
            if not sources and not staged_errors:
                if not args.quiet:
                    message = (
                        "No scannable staged changes."
                        if entries
                        else "No staged changes to scan."
                    )
                    print(message)
                return EXIT_CLEAN
            result = scanner.scan_sources(sources)
            result.errors.extend(staged_errors)
        else:
            scanner = Scanner(display_root=os.getcwd(), **scanner_options)
            ignore = load_default_ignore([os.getcwd()], excludes=args.exclude)
            result = scanner.scan(paths, ignore=ignore)
    except KeyboardInterrupt:
        print("sentinel: interrupted", file=sys.stderr)
        return 130

    if not args.quiet:
        for error in result.errors:
            print(f"sentinel: warning: {error}", file=sys.stderr)

    color = not args.no_color and supports_color(sys.stdout)
    if args.json:
        print(render_json(result, show_secrets=args.show_secrets))
    elif not args.quiet:
        print_report(
            result,
            show_secrets=args.show_secrets,
            color=color,
        )

    threshold = SEVERITY_RANK.get(args.fail_on)
    if result.files_scanned == 0 and result.errors:
        return EXIT_ERROR
    if threshold is None or result.highest_severity is None:
        return EXIT_CLEAN
    if SEVERITY_RANK[result.highest_severity] >= threshold:
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
