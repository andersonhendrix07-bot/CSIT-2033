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

You need Python 3.11 or newer. Check with `py -0p`. Nothing is installed outside the project folder, and you don't need git, uv or admin rights.

1. On GitHub, open the repo, switch to the `claude/dazzling-thompson-97srl7` branch, then choose **Code → Download ZIP**. Extract it, for example to `C:\Users\<you>\hostguard-src`.
2. In a **normal** (not admin) PowerShell window:

```powershell
cd C:\Users\<you>\hostguard-src\CSIT-2033-claude-dazzling-thompson-97srl7\hostguard
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation .
.\.venv\Scripts\hostguard.exe info
.\.venv\Scripts\python.exe -m pytest
```

How the lock files work:
- `--require-hashes` makes pip refuse any package whose SHA-256 doesn't match the lock file.
- `requirements.lock` has only the runtime packages. `requirements-dev.lock` adds pytest, ruff and mypy.
- Both files are generated from `uv.lock`.

The commands call the venv's programs directly, so you don't need `Activate.ps1`. That script is blocked by PowerShell's default execution policy, and hostguard never asks you to change that policy.

If you install [uv](https://docs.astral.sh/uv/) later, `uv sync --all-extras` then `uv run hostguard info` does the same thing.

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
# after changing dependencies, regenerate the hashed pip lock files:
uv export --all-extras --no-dev --group build --no-emit-project -o requirements.lock
uv export --all-extras --group build --no-emit-project -o requirements-dev.lock
uv run ruff check . && uv run ruff format --check .
uv run mypy
```

## Limitations (current)

- Only `info` and `config` work so far.
- Development and testing happen on Linux (Ubuntu 24.04). The Windows-specific code paths in `sysinfo.py` (Windows 11 edition and build detection, `IsUserAnAdmin`) are covered by mocked tests built from the target PC's real values (Windows 11 Home, build 26200), but haven't yet run on Windows itself.
