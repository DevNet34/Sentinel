import math
import re
import string
from collections import Counter

from .rules import looks_like_placeholder

TOKEN_RE = re.compile(r"[A-Za-z0-9+/\-_]{20,}")

MIN_LENGTH = 24
MIN_ENTROPY = 4.5
MIN_SEQUENTIAL_RUN = 6
MIN_CASE_RUN = 12
HASH_PREFIXES = ("sha1-", "sha256-", "sha384-", "sha512-", "md5-")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def longest_ascending_run(token: str) -> int:
    best = 1
    current = 1
    for previous, char in zip(token, token[1:]):
        if ord(char) == ord(previous) + 1:
            current += 1
            best = max(best, current)
        else:
            current = 1
    return best


def longest_same_case_run(token: str) -> int:
    best = 1
    current = 1
    for previous, char in zip(token, token[1:]):
        if char.isalpha() and previous.isalpha() and char.isupper() == previous.isupper():
            current += 1
            best = max(best, current)
        else:
            current = 1
    return best


def is_high_entropy_token(token: str) -> bool:
    if len(token) < MIN_LENGTH:
        return False
    if not any(ch.islower() for ch in token):
        return False
    if not any(ch.isupper() for ch in token):
        return False
    if not any(ch.isdigit() for ch in token):
        return False
    if all(ch in string.hexdigits for ch in token):
        return False
    if "=" in token.rstrip("="):
        return False
    if token.lower().startswith(HASH_PREFIXES):
        return False
    if token.startswith(("-", "/", "\\")) or "://" in token:
        return False
    if token.count("/") > 1:
        return False
    if longest_ascending_run(token) >= MIN_SEQUENTIAL_RUN:
        return False
    if longest_same_case_run(token) >= MIN_CASE_RUN:
        return False
    if looks_like_placeholder(token):
        return False
    return shannon_entropy(token) >= MIN_ENTROPY
