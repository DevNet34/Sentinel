import fnmatch
import os
import posixpath
import re
from typing import Iterable, List, Optional, Tuple

DEFAULT_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    "vendor",
    ".idea",
    ".vscode",
    ".next",
    ".nuxt",
    "coverage",
    "htmlcov",
}

SKIP_FILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
}

SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".bmp",
    ".tiff",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".tar",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".class",
    ".jar",
    ".war",
    ".pyc",
    ".pyo",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".mp3",
    ".mp4",
    ".mov",
    ".avi",
    ".webm",
    ".wav",
    ".flac",
    ".ogg",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".bin",
    ".dat",
    ".lock",
}

IGNORE_FILES = (".gitignore", ".sentinelignore")


class IgnoreRules:
    def __init__(self) -> None:
        self._rules: List[Tuple[bool, "re.Pattern[str]", bool, bool, bool]] = []

    def __bool__(self) -> bool:
        return bool(self._rules)

    def add_lines(self, lines: Iterable[str]) -> None:
        for line in lines:
            self._add(line.strip())

    def _add(self, line: str) -> None:
        if not line or line.startswith("#"):
            return
        negated = line.startswith("!")
        if negated:
            line = line[1:].strip()
        directory_only = line.endswith("/")
        line = line.rstrip("/")
        if not line:
            return
        anchored = line.startswith("/")
        if anchored:
            line = line[1:]
        has_slash = "/" in line
        translated = fnmatch.translate(line)
        self._rules.append(
            (negated, re.compile(translated), directory_only, anchored, has_slash)
        )

    def add_file(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                self.add_lines(handle)
        except OSError:
            return

    def load_from_dir(self, directory: str) -> None:
        for name in IGNORE_FILES:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                self.add_file(candidate)

    def matches(self, relative_path: str, is_dir: bool = False) -> bool:
        relative_path = relative_path.replace(os.sep, "/")
        basename = posixpath.basename(relative_path)
        ignored = False
        for negated, pattern, directory_only, anchored, has_slash in self._rules:
            if directory_only and not is_dir:
                continue
            candidate = relative_path if (anchored or has_slash) else basename
            if pattern.match(candidate):
                ignored = not negated
        return ignored

    def ignores_path(self, relative_path: str) -> bool:
        relative_path = relative_path.replace(os.sep, "/").strip("/")
        parts = relative_path.split("/")
        for index in range(1, len(parts)):
            if self.matches("/".join(parts[:index]), is_dir=True):
                return True
        return self.matches(relative_path, is_dir=False)


def should_skip_dir(name: str) -> bool:
    return name in DEFAULT_SKIP_DIRS or name.endswith(".egg-info")


def should_skip_path(relative_path: str) -> bool:
    parts = relative_path.replace(os.sep, "/").split("/")
    if any(should_skip_dir(part) for part in parts[:-1]):
        return True
    return should_skip_file(parts[-1])


def should_skip_file(name: str) -> bool:
    if name in SKIP_FILE_NAMES:
        return True
    _, extension = os.path.splitext(name)
    return extension.lower() in SKIP_EXTENSIONS


def load_default_ignore(directories: Iterable[str], excludes: Optional[Iterable[str]] = None) -> IgnoreRules:
    rules = IgnoreRules()
    for directory in directories:
        rules.load_from_dir(directory)
    if excludes:
        rules.add_lines(excludes)
    return rules
