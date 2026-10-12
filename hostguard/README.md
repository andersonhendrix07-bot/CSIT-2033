# hostguard

A local-only, defensive security tool for a single computer. It combines:

- **Host vulnerability analysis**: software inventory, CVE matching and a read-only configuration audit.
- **Antivirus-style malware scanning**: hash reputation, YARA-X, ClamAV if installed, and explainable heuristics.

> hostguard **complements** your built-in antivirus (Microsoft Defender on Windows 11). It is **not** a replacement. Keep Defender on.

Primary target: **Windows 11**. The code is kept portable to Linux and macOS where practical.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Skeleton: CLI, config, logging, safe subprocess wrapper, secrets, tests | **done** |
| 2 | Inventory, vulnerability matching, configuration audit | planned |
| 3 | Scan engines: hash, YARA-X, ClamAV, heuristics | planned |
| 4 | Quarantine and updates | planned |
| 5 | Reports (JSON / HTML / terminal) | planned |
| 6 | Optional: real-time monitoring, scheduled scans, GUI | needs approval |
| 7 | Hardening (STRIDE, pip-audit) | planned |

Commands from later phases already appear in `--help`, but they exit with code 2 and say "not implemented yet".

## Install (Windows 11)

You need Python 3.11 or newer (`py -0p` lists the installed versions) and [uv](https://docs.astral.sh/uv/). Nothing is installed outside the project folder.

```powershell
git clone https://github.com/andersonhendrix07-bot/CSIT-2033.git
cd CSIT-2033\hostguard
uv sync --all-extras            # creates .venv with pinned dependencies (uv.lock)
uv run hostguard info
uv run pytest
```

Without uv, use plain pip. Direct dependencies are pinned in `pyproject.toml`, but sub-dependencies are not; only `uv.lock` pins the whole tree with hashes:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[keyring]" pytest==9.1.1 ruff==0.17.0 mypy==2.4.0
```

Run it **unelevated**. hostguard never needs Administrator rights to work. Checks that do need them are reported as "Skipped: requires admin".

## Usage

```text
hostguard [--config FILE] [-v|-vv|-q] [--no-color] COMMAND

  info                 host facts, hostguard folders, which API keys are set
  config path|show     where the config lives / effective settings
  config init [--force]  write a commented default config.toml
  vulns | audit        (Phase 2)
  scan                 (Phase 3)
  quarantine | update  (Phase 4)
  report               (Phase 5)
```

Exit codes: `0` clean, `1` findings, `2` error.

### Files and folders

| What | Windows 11 default |
|---|---|
| Config | `%LOCALAPPDATA%\hostguard\config.toml` |
| Data (rules, hashes, quarantine) | `%LOCALAPPDATA%\hostguard\` |
| Cache | `%LOCALAPPDATA%\hostguard\Cache` |
| Log (rotating, UTF-8) | `%LOCALAPPDATA%\hostguard\Logs\hostguard.log` |

Set `HOSTGUARD_HOME` to keep everything under one folder instead. `hostguard info` prints the actual paths.

### API keys (optional)

Keys come from environment variables, or from the Windows Credential Manager through `keyring` (service `hostguard`). They are never written to config files and are redacted from logs.

| Variable | Used for |
|---|---|
| `NVD_API_KEY` | NVD CVE API (optional; raises the rate limit) |
| `ABUSECH_AUTH_KEY` | MalwareBazaar hash exports (required for that feed; free from auth.abuse.ch) |
| `VT_API_KEY` | VirusTotal hash lookups (optional; off by default) |

```powershell
uv run python -c "import keyring; keyring.set_password('hostguard','NVD_API_KEY', input('key: '))"
```

## Architecture (so far)

```
src/hostguard/
  cli.py          argparse CLI, exit codes, top-level error handling
  config.py       TOML defaults + strict validation (unknown keys are errors)
  paths.py        per-user folders (platformdirs) and the scanner's self-exclusions
  logsetup.py     rotating log file + console; secret redaction filter
  credentials.py  API keys from env vars / keyring, never printed
  proc.py         the only subprocess entry point: list argv, no shell, timeouts, CWD-planting guard
  sysinfo.py      OS / build / architecture / elevation
  models.py       Finding, Evidence, Verdict, Severity, Confidence, ExitCode
```

## Development

```bash
uv run pytest            # tests; real network access makes a test fail
uv run ruff check . && uv run ruff format --check .
uv run mypy
```

## Limitations (current)

- Only `info` and `config` work so far.
- Development and testing happen on Linux (Ubuntu 24.04). The Windows-specific code paths in `sysinfo.py` (Windows 11 detection, `IsUserAnAdmin`) are covered by mocked tests only until they have been run on a real Windows 11 machine.
