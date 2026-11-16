import re
from dataclasses import dataclass
from typing import Callable, List, Optional

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

PLACEHOLDER_WORDS = {
    "example",
    "sample",
    "dummy",
    "test",
    "testing",
    "fake",
    "placeholder",
    "redacted",
    "changeme",
    "change_me",
    "change-me",
    "replace_me",
    "replace-me",
    "your_key",
    "your-key",
    "yourkey",
    "yourtoken",
    "your_token",
    "yoursecret",
    "your_secret",
    "xxxxxxxx",
    "xxxx",
    "abc123",
    "password",
    "secret",
    "token",
    "apikey",
    "api_key",
    "none",
    "null",
    "true",
    "false",
    "todo",
    "fixme",
}

_PLACEHOLDER_FRAGMENTS = (
    "your_",
    "your-",
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "change-me",
    "dummy",
    "redacted",
    "goes-here",
    "goes_here",
    "insert_",
    "<",
    ">",
    "${",
    "{{",
    "}}",
    "%s",
    "getenv",
    "environ",
    "process.env",
)


def looks_like_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("'\"`")
    if not cleaned:
        return True
    lowered = cleaned.lower()
    if lowered in PLACEHOLDER_WORDS:
        return True
    return any(fragment in lowered for fragment in _PLACEHOLDER_FRAGMENTS)


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: "re.Pattern[str]"
    severity: str
    description: str = ""
    group: int = 0
    validator: Optional[Callable[["re.Match[str]"], bool]] = None
    pii: bool = False

    def extract(self, match: "re.Match[str]") -> str:
        return match.group(self.group)


def luhn_valid(number: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


CARD_PREFIXES = ("34", "37", "36", "38", "39")
CARD_RANGES_2 = ((51, 55),)
CARD_RANGES_3 = ((300, 305), (644, 649))
CARD_RANGES_4 = ((2221, 2720), (3528, 3589))
CARD_RANGES_6 = ((622126, 622925),)


def _known_card_prefix(digits: str) -> bool:
    if digits.startswith("4"):
        return True
    if digits[:2] in CARD_PREFIXES:
        return True
    if digits.startswith("65") or digits.startswith("6011"):
        return True
    for low, high in CARD_RANGES_2:
        if low <= int(digits[:2]) <= high:
            return True
    for low, high in CARD_RANGES_3:
        if low <= int(digits[:3]) <= high:
            return True
    for low, high in CARD_RANGES_4:
        if low <= int(digits[:4]) <= high:
            return True
    for low, high in CARD_RANGES_6:
        if low <= int(digits[:6]) <= high:
            return True
    return False


def _valid_credit_card(match: "re.Match[str]") -> bool:
    digits = re.sub(r"\D", "", match.group(0))
    if not luhn_valid(digits):
        return False
    return _known_card_prefix(digits)


PROSE_MARKERS = (
    "used",
    "your",
    " the ",
    " for ",
    " with ",
    "here",
    "example",
    "placeholder",
    "change",
    "generate",
    "sample",
)


def _valid_generic(match: "re.Match[str]") -> bool:
    value = match.group(1).strip()
    if looks_like_placeholder(value):
        return False
    if re.fullmatch(r"[A-Za-z0-9_.\-]+#[A-Za-z0-9_.\-]+", value):
        return False
    if re.match(r"(?:https?|ftp|file|urn):", value, re.I):
        return False
    if re.match(r"(?:/|~/|[A-Za-z]:[\\/])", value):
        return False
    if " " in value and any(marker in value.lower() for marker in PROSE_MARKERS):
        return False
    return True


def _valid_private_key(match: "re.Match[str]") -> bool:
    line_start = match.string.rfind("\n", 0, match.start()) + 1
    line_end = match.string.find("\n", match.end())
    if line_end == -1:
        line_end = len(match.string)
    line = match.string[line_start:line_end]
    return not re.search(r"x{4,}|example|placeholder|your", line, re.I)


def _valid_unquoted(match: "re.Match[str]") -> bool:
    value = match.group(1)
    if looks_like_placeholder(value):
        return False
    if len(value) < 12:
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", value):
        return False
    if not re.search(r"[0-9]", value) and not re.search(r"[^A-Za-z0-9_]", value):
        return False
    return True


def _valid_secret_value(match: "re.Match[str]") -> bool:
    return not looks_like_placeholder(match.group(1))


RULES: List[Rule] = [
    Rule(
        "private-key",
        "Private key block",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
        "critical",
        "PEM/OpenSSH private key material.",
        validator=_valid_private_key,
    ),
    Rule(
        "aws-access-key",
        "AWS access key ID",
        re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        "high",
        "Amazon Web Services access key identifier.",
    ),
    Rule(
        "aws-secret-key",
        "AWS secret access key",
        re.compile(
            r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        "critical",
        "Amazon Web Services secret access key.",
        group=1,
        validator=_valid_secret_value,
    ),
    Rule(
        "github-token",
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
        "high",
        "GitHub personal access or app token.",
    ),
    Rule(
        "gitlab-token",
        "GitLab token",
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
        "high",
        "GitLab personal access token.",
    ),
    Rule(
        "slack-token",
        "Slack token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
        "high",
        "Slack bot, user or app token.",
    ),
    Rule(
        "stripe-live-key",
        "Stripe live key",
        re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b"),
        "critical",
        "Stripe live secret or restricted key.",
    ),
    Rule(
        "stripe-test-key",
        "Stripe test key",
        re.compile(r"\b(?:sk|rk)_test_[0-9a-zA-Z]{16,}\b"),
        "medium",
        "Stripe test secret or restricted key.",
    ),
    Rule(
        "google-api-key",
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "high",
        "Google API key.",
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
        ),
        "medium",
        "Signed JSON Web Token; may embed long-lived claims.",
    ),
    Rule(
        "npm-token",
        "npm token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "high",
        "npm registry access token.",
    ),
    Rule(
        "sendgrid-key",
        "SendGrid API key",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,}\b"),
        "high",
        "SendGrid API key.",
    ),
    Rule(
        "huggingface-token",
        "Hugging Face token",
        re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
        "high",
        "Hugging Face access token.",
    ),
    Rule(
        "digitalocean-token",
        "DigitalOcean token",
        re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
        "high",
        "DigitalOcean personal access token.",
    ),
    Rule(
        "openai-key",
        "OpenAI API key",
        re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b"),
        "high",
        "OpenAI project API key.",
    ),
    Rule(
        "anthropic-key",
        "Anthropic API key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
        "high",
        "Anthropic API key.",
    ),
    Rule(
        "discord-webhook",
        "Discord webhook URL",
        re.compile(
            r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,25}/[A-Za-z0-9_\-]{50,}"
        ),
        "high",
        "Discord webhook URL that allows posting to a channel.",
    ),
    Rule(
        "generic-secret",
        "Hard-coded credential",
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|"
            r"auth[_-]?token|private[_-]?key|password|passwd|pwd)\b[\"']?\s*[:=]\s*"
            r"[\"']([^\"'\n]{8,})[\"']"
        ),
        "medium",
        "Credential-like value assigned in source code.",
        group=1,
        validator=_valid_generic,
    ),
    Rule(
        "generic-secret-unquoted",
        "Unquoted credential",
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|"
            r"auth[_-]?token|private[_-]?key|password|passwd|pwd)\b[\"']?\s*[:=]\s*"
            r"([A-Za-z0-9_\-./+=]{12,})"
        ),
        "medium",
        "Unquoted credential-like value such as in a .env file.",
        group=1,
        validator=_valid_unquoted,
    ),
    Rule(
        "credit-card",
        "Credit card number",
        re.compile(
            r"(?<![\w.])(?:"
            r"\d{4}(?:[ -]\d{4}){2}[ -]\d{1,4}"
            r"|\d{4}[ -]\d{6}[ -]\d{5}"
            r"|\d{13,19}"
            r")(?![\w.])"
        ),
        "high",
        "Payment card number that passes the Luhn checksum.",
        validator=_valid_credit_card,
        pii=True,
    ),
    Rule(
        "ssn",
        "US Social Security number",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        "high",
        "US Social Security number.",
        pii=True,
    ),
]

RULES_BY_ID = {rule.id: rule for rule in RULES}


def get_rules(include_pii: bool = True) -> List[Rule]:
    return [rule for rule in RULES if include_pii or not rule.pii]
