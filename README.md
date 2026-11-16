# Sentinel
Offline CLI that scans source code and staged git changes for leaked secrets and sensitive data.

A dependency-free CLI that finds leaked secrets and sensitive data in your code
**before** they reach a remote, a build log, or a container image.

Credential leakage is one of the most common root causes of data breaches: a
single committed API key or private key can hand an attacker your cloud bill,
customer data, or production infrastructure. Sentinel is a fast, local, offline
check you can run on every commit.

## Features

- 21 detectors: AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic,
  SendGrid, npm, Hugging Face, DigitalOcean, Discord webhooks, JWTs, private
  keys, credit cards, SSNs, hard-coded credentials, and unquoted `.env`-style
  assignments.
- High-entropy string detection for secrets that do not match a known format.
  Identifier-like tokens, alphabets, digests, and comment lines are filtered.
- Credit-card validation via the Luhn checksum; placeholder filtering to cut
  false positives.
- Redacted output by default, so scanning does not print secrets to logs.
- Honors `.gitignore`, `.sentinelignore`, built-in dependency/binary skips, and
  inline `sentinel:ignore` markers.
- `--staged` mode for pre-commit hooks (scans the git index, including renames),
  JSON output for pipelines, sensible exit codes, and zero third-party
  dependencies.

## Install

```bash
cd sentinel
pip install .
```

This installs the `sentinel` command. For development you can run it without
installing, but you must run it **from the repository root**:

```bash
cd sentinel
python3 -m sentinel --help
```

Running `python3 -m sentinel` from the parent directory does not work: the
project folder itself is named `sentinel` and Python treats it as a namespace
package without `__main__.py`. Install the package or use
`PYTHONPATH=/path/to/sentinel python3 -m sentinel` to run it elsewhere.

## Usage

See [USAGE.md](USAGE.md) for the full guide, including CI and hook examples.

```bash
sentinel .                       # scan the current directory
sentinel src/ examples/          # scan specific paths
sentinel --staged                # scan only files staged in git (index contents)
sentinel --json > report.json    # machine-readable report
sentinel --fail-on high          # exit 1 only for high/critical findings
sentinel --list-rules            # show every detector
```

Exit codes (`--fail-on` defaults to `low`):

| Code | Meaning                                      |
|------|----------------------------------------------|
| 0    | no findings at or above the `--fail-on` level |
| 1    | findings at or above the `--fail-on` level    |
| 2    | usage or environment error                    |

### Inline suppression

```python
EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"   # sentinel:ignore
# sentinel:ignore-next-line
fake = "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R"
```

### Pre-commit hook

```bash
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/sh
exec sentinel --staged --fail-on high
EOF
chmod +x .git/hooks/pre-commit
```

### Examples

All credentials in `examples/` are fake placeholders used to demonstrate the
detectors. Do not replace them with real credentials.

```bash
$ sentinel examples --no-color
SEVERITY  RULE                   LOCATION                        MATCH
critical  Private key block      examples/leaked_config.py:7:16  -----BEGIN RSA PRIVATE KEY-----
high      AWS access key ID      examples/leaked_config.py:3:22  AKIA************LE
high      GitHub token           examples/leaked_config.py:4:17  ghp_************8R
medium    Hard-coded credential  examples/leaked_config.py:5:16  corr************le
medium    High-entropy string    examples/leaked_config.py:6:17  Zx9Q************d1

Scanned 1 files (316 B) in 0.00s - 5 findings (1 critical, 2 high, 2 medium)
```

## Configuration

Create `.sentinelignore` in the scanned directory using gitignore syntax:

```gitignore
tests/fixtures/
*.min.js
```

Use `--exclude GLOB` for one-off exclusions. Files larger than `--max-size`
(default 1 MB), binaries, lockfiles, and dependency folders are skipped.

## Limitations

- Detection is pattern-based; it is a safety net, not a substitute for secret
  managers, least-privilege credentials, or rotating keys that were exposed.
- Entropy detection is heuristic. It ignores comment lines and filters
  identifier-like tokens, alphabets, hashes, and digests; use `--no-entropy` if
  it is still too noisy.
- Ignore files are loaded from the scanned roots (plus the current directory),
  not from every nested directory.  
- If a secret has already been pushed, rotate it. Removing it from the working
  tree is not enough.
----------------------------------------------------------------------------------------------------------------------
#For contributions 
BTC: bc1qvx72nmrxg7u6xdp6u62wnpns72dcrmtfwz8hrg 
ETH: 0x37DDd7c1b7fB3a7488501b250b41beacFc776d47
SOL: 3iVxADKWroSpVc9JA1jSpGjFZZ2Y6XtqHJZYttDvNf36

MI T
