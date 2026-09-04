# passforge

An industrial-grade, asynchronous CLI password and passphrase generator, built as
a security-tooling portfolio piece. It generates cryptographically secure
alphanumeric strings, complex passwords, and EFF-wordlist passphrases under
enforceable policy constraints, with full accountability logging of every
generation and export event.

## Problem Statement

Most "password generator" scripts are single-function utilities: they produce
a random string and stop there. That's insufficient for anything resembling a
real security tool, which needs to:

- Enforce a **configurable policy** (length bounds, minimum digit/special/
  upper/lower counts, exclusion of visually-similar or user-forbidden
  characters) and prove compliance rather than assume it.
- Support **multiple generation strategies** — random alphanumeric, complex
  (full symbol set), and memorable EFF-wordlist passphrases — behind one
  consistent interface.
- Handle **bulk generation efficiently** without serializing large `--count`
  requests behind a single blocking loop.
- Leave an **auditable trail**. In a professional/enterprise context, "a
  password was generated" is an event someone may need to review later —
  who ran it, when, with what policy, and whether it succeeded.
- Fail **loudly and specifically**. A generic `Exception` with a string
  message is not good enough for an audit log or an on-call engineer;
  failures need structured error codes and context.

`passforge` solves this with a layered architecture: policy validation in the
model layer, character-pool and generation logic in the service layer
(fully async, with concurrent bulk generation via `asyncio.gather`), a
structured exception hierarchy with project-prefixed error codes, and a
non-blocking dual-sink logger (colored console + JSON-lines audit file).

## Features

- **Three generation categories**: alphanumeric, complex, and EFF-wordlist
  passphrases (basic / strong / paranoid strength tiers).
- **Policy engine**: configurable min/max length, minimum digit/special/
  upper/lowercase counts, similar-character exclusion, custom exclusion
  sets — validated explicitly and rejected with structured errors if
  self-contradictory.
- **Fully async core**: passphrase assembly and file I/O run natively async;
  fixed-charset generation attempts are offloaded via `asyncio.to_thread`
  so bulk requests fan out concurrently under a bounded semaphore instead
  of serializing.
- **25+ custom exceptions** across input validation, policy, character-pool,
  wordlist, export, concurrency, logging, and CLI domains — each with a
  `PFG-xxxx` error code, severity, timestamp, and structured context dict.
  Fully picklable and usable as mappings (`err["key"]`, `"key" in err`).
- **Non-blocking accountability logging**: `QueueHandler`/`QueueListener`
  dual sink — ANSI-colored console output plus a JSON-lines audit trail
  (`logs/passforge_audit.jsonl`) recording every request, success, failure,
  and export.
- **Dual CLI modes**: `argparse` for scripted/automation use, and an
  interactive REPL wizard with `readline` history for manual use.
- **JSON/CSV export** of results, async, with metadata.
- **Bash tooling**: `run.sh` bootstraps a virtualenv and Python-version
  check; `bin/passforge` is a wrapper adding `tail-log` (audit log viewer)
  and `batch` (CSV-driven bulk runs) on top of the Python CLI.
- **68-test pytest suite** covering models, services, exceptions, and the
  generator's async/concurrent paths.

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/kavineksith/passforge.git
cd passforge
chmod +x run.sh bin/passforge
```

Place your `eff_large_wordlist.txt` in the project root (required only for
`--category passphrase`).

`run.sh` handles virtual environment creation and dependency installation
automatically on first run — no manual `pip install` needed for normal use.

## Usage

### Scripted / automation mode

```bash
./run.sh --length 16 --category complex --strength strong --count 3
```

Or via the bash wrapper (identical behavior, same flags):

```bash
bin/passforge --length 16 --category complex --strength strong --count 3
bin/passforge gen --length 16 --category complex   # equivalent, explicit subcommand
```

**Arguments:**

| Argument               | Description                                                   | Required |
|-------------------------|-----------------------------------------------------------------|----------|
| `--length`              | Password length, or word count for passphrases                | Yes      |
| `--category`            | `alphanumeric`, `complex`, `passphrase`                        | Yes      |
| `--strength`            | `basic`, `strong`, `paranoid` (default: `strong`)               | No       |
| `--count`               | Number of results to generate (default: `1`)                    | No       |
| `--output`              | Save results to `.json` or `.csv`                               | No       |
| `--max-concurrency`     | Concurrent worker cap for bulk generation (default: `16`)       | No       |
| `--wordlist`            | Path to EFF wordlist file (default: `eff_large_wordlist.txt`)   | No       |
| `--exclude-chars`       | Characters to exclude from generation                           | No       |
| `--no-exclude-similar`  | Keep visually similar characters (l, 1, I, o, O, 0)              | No       |
| `--log-dir`             | Directory for the audit log (default: `logs`)                   | No       |
| `--quiet`               | Suppress console log output (audit file still written)          | No       |

### Interactive mode

Run with no arguments for a guided wizard:

```bash
./run.sh
```

### Bash convenience commands

```bash
bin/passforge tail-log 20        # view the last 20 audit log entries
bin/passforge batch specs.csv    # run one generation per CSV row: length,category,strength,count,output
```

### Python API

```python
import asyncio
from passforge.models.policy import PasswordPolicy
from passforge.services.generator import PasswordGeneratorService
from passforge.core.enums import PasswordCategory, PasswordStrength

async def main():
    service = PasswordGeneratorService(policy=PasswordPolicy(min_length=12))
    results = await service.generate_many(5, 16, PasswordCategory.COMPLEX, PasswordStrength.PARANOID)
    for r in results:
        print(r.value, r.entropy_bits)

asyncio.run(main())
```

## Architecture

```
passforge/
├── core/          exceptions, enums, non-blocking dual-sink logger
├── models/        PasswordPolicy, GeneratedPassword (full dunder suite)
├── services/       CharacterPool, WordlistService, PasswordGeneratorService, ResultExporter
├── cli/            argparse definitions, interactive REPL, main entrypoint
└── tests/          68 pytest tests across all layers
```

## Troubleshooting

- **`PFG-1401 Wordlist file not found`**: place `eff_large_wordlist.txt` in
  the project root, or pass `--wordlist /path/to/file.txt`.
- **`PFG-1301 Character pool is empty after exclusions`**: your
  `--exclude-chars` value removed an entire required character class (e.g.
  excluding all digits while the policy requires `min_digits >= 1`). Loosen
  the exclusion set or lower the corresponding policy minimum.
- **`PFG-1202 Invalid password policy configuration`**: the sum of your
  minimum digit/special/upper/lower requirements exceeds `max_length`, or
  `min_length > max_length`. Check the reported `errors` list in the
  message context.
- **`PFG-1203 Generation exhausted retry budget`**: the requested length is
  too short to satisfy all policy minimums reliably within 100 attempts.
  Increase length or relax policy minimums.
- **Permission denied running `run.sh` / `bin/passforge`**: run
  `chmod +x run.sh bin/passforge`.
- **`pip install` fails inside `run.sh`**: ensure Python 3.11+ and the `venv`
  module are available (`apt install python3-venv` on Debian/Ubuntu).
- Full detail on any failure is available in `logs/passforge_audit.jsonl`
  (or `bin/passforge tail-log`), including error code, severity, and context.

## Testing

```bash
. .venv/bin/activate
pip install -e ".[dev]"
pytest passforge/tests -v
```

## Disclaimer

This software is provided for educational and professional portfolio
purposes. It uses Python's `secrets` module for cryptographically secure
randomness in `strong`/`paranoid` modes (`basic` mode intentionally uses the
non-cryptographic `random` module and should not be used to generate
credentials for real accounts). This tool is **not** a substitute for a
vetted, audited enterprise password/secrets management system. The authors
make no guarantees about fitness for any particular purpose and accept no
liability for credentials generated, stored, or lost using this software.
Use at your own risk, and never commit generated credentials to version
control.

## License

MIT License. See [LICENSE](LICENSE) for details.
