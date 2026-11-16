import bisect
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .entropy import TOKEN_RE, is_high_entropy_token
from .ignore import (
    IgnoreRules,
    should_skip_dir,
    should_skip_file,
)
from .rules import SEVERITY_RANK, RULES_BY_ID, Rule, get_rules


def redact(value: str) -> str:
    value = value.strip()
    if value.startswith("-----BEGIN"):
        return value
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * min(12, len(value) - 6) + value[-2:]


@dataclass
class Finding:
    path: str
    line: int
    column: int
    rule_id: str
    rule_name: str
    severity: str
    match: str

    def to_dict(self, show_secrets: bool = False) -> Dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "match": self.match if show_secrets else redact(self.match),
        }


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    elapsed: float = 0.0
    errors: List[str] = field(default_factory=list)

    @property
    def highest_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda item: SEVERITY_RANK[item.severity]).severity

    def counts(self) -> Dict[str, int]:
        counts = {name: 0 for name in SEVERITY_RANK}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts


class Scanner:
    def __init__(
        self,
        use_entropy: bool = True,
        include_pii: bool = True,
        max_size: int = 1_000_000,
        display_root: Optional[str] = None,
    ) -> None:
        self.rules = get_rules(include_pii=include_pii)
        self.use_entropy = use_entropy
        self.max_size = max_size
        self.display_root = os.path.abspath(display_root or os.getcwd())
        self._findings: List[Finding] = []
        self._errors: List[str] = []
        self._files = 0
        self._bytes = 0

    def scan(
        self, paths: Sequence[str], ignore: Optional[IgnoreRules] = None
    ) -> ScanResult:
        started = time.perf_counter()
        self._reset()
        active_rules = ignore or IgnoreRules()
        for raw in paths:
            target = os.path.abspath(raw)
            if os.path.isdir(target):
                active_rules.load_from_dir(target)
                self._scan_directory(target, active_rules)
            elif os.path.isfile(target):
                self._scan_file(target)
            else:
                self._errors.append(f"path not found: {raw}")
        return self._finalize(started)

    def scan_sources(self, sources: Sequence[Tuple[str, bytes]]) -> ScanResult:
        started = time.perf_counter()
        self._reset()
        for display_path, data in sources:
            if not data:
                continue
            if len(data) > self.max_size:
                self._errors.append(
                    f"skipped large file {display_path} ({len(data)} bytes)"
                )
                continue
            if b"\x00" in data[:4096]:
                continue
            text = data.decode("utf-8", errors="replace")
            self._files += 1
            self._bytes += len(data)
            self._findings.extend(self._scan_text(text, display_path))
        return self._finalize(started)

    def _reset(self) -> None:
        self._findings = []
        self._errors = []
        self._files = 0
        self._bytes = 0

    def _finalize(self, started: float) -> ScanResult:
        self._findings.sort(
            key=lambda item: (
                -SEVERITY_RANK[item.severity],
                item.path,
                item.line,
                item.column,
            )
        )
        return ScanResult(
            findings=self._findings,
            files_scanned=self._files,
            bytes_scanned=self._bytes,
            elapsed=time.perf_counter() - started,
            errors=self._errors,
        )

    def _display_path(self, path: str) -> str:
        absolute = os.path.abspath(path)
        try:
            relative = os.path.relpath(absolute, self.display_root)
        except ValueError:
            return absolute
        if relative.startswith(".." + os.sep) or relative == "..":
            return absolute
        return relative

    def _scan_directory(self, directory: str, ignore: IgnoreRules) -> None:
        for root, dirnames, filenames in os.walk(directory, topdown=True):
            kept_dirs = []
            for dirname in sorted(dirnames):
                if should_skip_dir(dirname):
                    continue
                full = os.path.join(root, dirname)
                if ignore.matches(self._display_path(full), is_dir=True):
                    continue
                kept_dirs.append(dirname)
            dirnames[:] = kept_dirs
            for filename in sorted(filenames):
                if should_skip_file(filename):
                    continue
                full = os.path.join(root, filename)
                if ignore.matches(self._display_path(full), is_dir=False):
                    continue
                self._scan_file(full)

    def _scan_file(self, path: str) -> None:
        display = self._display_path(path)
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            self._errors.append(f"cannot stat {display}: {exc}")
            return
        if size == 0:
            return
        if size > self.max_size:
            self._errors.append(f"skipped large file {display} ({size} bytes)")
            return
        try:
            with open(path, "rb") as handle:
                head = handle.read(4096)
                if b"\x00" in head:
                    return
                data = head + handle.read()
        except OSError as exc:
            self._errors.append(f"cannot read {display}: {exc}")
            return
        text = data.decode("utf-8", errors="replace")
        self._files += 1
        self._bytes += len(data)
        self._findings.extend(self._scan_text(text, display))

    def _scan_text(self, text: str, display_path: str) -> List[Finding]:
        line_starts = [0]
        for index, character in enumerate(text):
            if character == "\n":
                line_starts.append(index + 1)

        suppressed = set()
        for index, start in enumerate(line_starts):
            end = line_starts[index + 1] if index + 1 < len(line_starts) else len(text)
            line_text = text[start:end]
            if "sentinel:ignore-next-line" in line_text:
                suppressed.add(index + 2)
            elif "sentinel:ignore" in line_text:
                suppressed.add(index + 1)

        def line_of(offset: int) -> int:
            return bisect.bisect_right(line_starts, offset)

        longest_line = max(
            [line_starts[index + 1] - line_starts[index] for index in range(len(line_starts) - 1)]
            + [len(text) - line_starts[-1]]
        )
        generated = longest_line > 2000

        findings: List[Finding] = []
        reported_spans: List[Tuple[int, int, int]] = []

        def overlaps(line: int, start: int, end: int) -> bool:
            return any(
                line == other_line and not (end <= other_start or start >= other_end)
                for other_line, other_start, other_end in reported_spans
            )

        for rule in self.rules:
            if rule.id == "generic-secret":
                continue
            if generated and rule.pii:
                continue
            for match in rule.pattern.finditer(text):
                if match.start() == match.end():
                    continue
                line = line_of(match.start())
                if line in suppressed:
                    continue
                if rule.validator is not None and not rule.validator(match):
                    continue
                secret = rule.extract(match)
                if not secret:
                    continue
                secret_start = match.start(rule.group) if rule.group else match.start()
                column = secret_start - line_starts[line - 1] + 1
                findings.append(
                    Finding(
                        path=display_path,
                        line=line,
                        column=column,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        match=secret,
                    )
                )
                reported_spans.append((line, match.start(), match.end()))

        generic = RULES_BY_ID.get("generic-secret")
        if generic is not None and generic in self.rules:
            for match in generic.pattern.finditer(text):
                line = line_of(match.start())
                if line in suppressed:
                    continue
                if generic.validator is not None and not generic.validator(match):
                    continue
                value_start, value_end = match.span(1)
                if overlaps(line, value_start, value_end):
                    continue
                secret = generic.extract(match)
                if not secret:
                    continue
                column = value_start - line_starts[line - 1] + 1
                findings.append(
                    Finding(
                        path=display_path,
                        line=line,
                        column=column,
                        rule_id=generic.id,
                        rule_name=generic.name,
                        severity=generic.severity,
                        match=secret,
                    )
                )
                reported_spans.append((line, value_start, value_end))

        comment_prefixes = ("#", "//", "/*", "*", "<!--", "--", ";", '"""', "'''")
        if self.use_entropy and not generated:
            for match in TOKEN_RE.finditer(text):
                token = match.group(0)
                line = line_of(match.start())
                if line in suppressed:
                    continue
                line_start_offset = line_starts[line - 1]
                line_end_offset = (
                    line_starts[line] if line < len(line_starts) else len(text)
                )
                line_text = text[line_start_offset:line_end_offset].lstrip()
                if line_text.startswith(comment_prefixes):
                    continue
                if overlaps(line, match.start(), match.end()):
                    continue
                if not is_high_entropy_token(token):
                    continue
                column = match.start() - line_starts[line - 1] + 1
                findings.append(
                    Finding(
                        path=display_path,
                        line=line,
                        column=column,
                        rule_id="high-entropy",
                        rule_name="High-entropy string",
                        severity="medium",
                        match=token,
                    )
                )
                reported_spans.append((line, match.start(), match.end()))

        return findings
