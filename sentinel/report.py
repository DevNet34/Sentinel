import json
import os
import sys
from typing import Dict, List, Optional, Sequence, TextIO, Tuple

from .scanner import Finding, ScanResult, redact

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

SEVERITY_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
}


def supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _truncate(value: str, width: int) -> str:
    if width <= 0 or len(value) <= width:
        return value
    return value[: width - 1] + "~"


def _human_bytes(count: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(count)
    index = 0
    while value >= 1024 and index < len(units) - 1:
        value /= 1024
        index += 1
    if index == 0:
        return f"{int(value)} {units[index]}"
    return f"{value:.1f} {units[index]}"


def _rows(
    findings: Sequence[Finding], show_secrets: bool
) -> List[Tuple[str, str, str, str]]:
    rows: List[Tuple[str, str, str, str]] = []
    for finding in findings:
        location = f"{finding.path}:{finding.line}:{finding.column}"
        match = finding.match if show_secrets else redact(finding.match)
        rows.append((finding.severity, finding.rule_name, location, match))
    return rows


def render_table(
    findings: Sequence[Finding], show_secrets: bool = False, color: bool = True
) -> str:
    rows = [("SEVERITY", "RULE", "LOCATION", "MATCH")]
    rows.extend(_rows(findings, show_secrets))
    limits = (8, 26, 64, 44)
    widths = []
    for index, limit in enumerate(limits):
        width = max(len(_truncate(row[index], limit)) for row in rows)
        widths.append(min(width, limit))

    lines = []
    for row_index, row in enumerate(rows):
        cells = []
        for column_index, cell in enumerate(row):
            truncated = _truncate(cell, limits[column_index])
            padded = truncated.ljust(widths[column_index])
            if row_index > 0 and column_index == 0 and color:
                padded = SEVERITY_COLORS[row[0]] + padded + RESET
            cells.append(padded)
        line = "  ".join(cells).rstrip()
        if row_index == 0 and color:
            line = BOLD + line + RESET
        lines.append(line)
    return "\n".join(lines)


def render_summary(result: ScanResult, color: bool = True) -> str:
    counts = result.counts()
    scanned = (
        f"Scanned {result.files_scanned} files "
        f"({_human_bytes(result.bytes_scanned)}) in {result.elapsed:.2f}s"
    )
    if not result.findings:
        message = f"{scanned} - no leaks found"
        return (BOLD + message + RESET) if color else message
    parts = []
    for severity in ("critical", "high", "medium", "low"):
        if counts[severity]:
            part = f"{counts[severity]} {severity}"
            if color:
                part = SEVERITY_COLORS[severity] + part + RESET
            parts.append(part)
    total = len(result.findings)
    breakdown = ", ".join(parts)
    message = f"{scanned} - {total} finding{'s' if total != 1 else ''} ({breakdown})"
    return (BOLD + message + RESET) if color else message


def render_json(result: ScanResult, show_secrets: bool = False) -> str:
    payload: Dict[str, object] = {
        "findings": [finding.to_dict(show_secrets=show_secrets) for finding in result.findings],
        "summary": {
            "files_scanned": result.files_scanned,
            "bytes_scanned": result.bytes_scanned,
            "elapsed_seconds": round(result.elapsed, 4),
            "counts": result.counts(),
            "errors": result.errors,
        },
    }
    return json.dumps(payload, indent=2)


def print_report(
    result: ScanResult,
    show_secrets: bool = False,
    color: bool = True,
    stream: Optional[TextIO] = None,
) -> None:
    target: TextIO = stream if stream is not None else sys.stdout
    if result.findings:
        target.write(render_table(result.findings, show_secrets, color) + "\n")
        target.write("\n")
    target.write(render_summary(result, color) + "\n")
