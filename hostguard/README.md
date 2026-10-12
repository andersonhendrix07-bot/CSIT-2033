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
| 2 | Inventory, vulnerability matching, configuration audit | **done** |
| 3 | Scan engines: hash, YARA-X, ClamAV, heuristics | planned |
| 4 | Quarantine and updates | planned |
| 5 | Reports (JSON / HTML / terminal) | planned |
| 6 | Optional: real-time monitoring, scheduled scans, GUI | needs approval |
| 7 | Hardening (STRIDE, pip-audit) | planned |

Commands from later phases (`scan`, `quarantine`, `update`, `report`) already appear in `--help`, but they exit with code 2 and say "not implemented yet".

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

  info                     host facts, hostguard folders, which API keys are set
  config path|show         where the config lives / effective settings
  config init [--force]    write a commented default config.toml
  inventory                OS build and updates, installed software, listening ports, startup entries
  vulns                    match installed software against known vulnerabilities
  audit                    read-only security configuration checks
  scan                     (Phase 3)
  quarantine | update      (Phase 4)
  report                   (Phase 5)
```

Exit codes: `0` clean, `1` findings, `2` error or incomplete result. `audit` returns 1 only for failed checks above "info" severity.

### Day-to-day examples (Windows, normal PowerShell)

```powershell
.\.venv\Scripts\hostguard.exe vulns                         # Windows build + desktop apps
.\.venv\Scripts\hostguard.exe vulns --python-env C:\proj\.venv # also check a Python project
.\.venv\Scripts\hostguard.exe vulns -v --json vulns.json      # details + machine-readable output
.\.venv\Scripts\hostguard.exe vulns --offline                 # cached data only (warns if stale)
.\.venv\Scripts\hostguard.exe audit -v                        # failed checks with evidence, fix, retest, links
.\.venv\Scripts\hostguard.exe inventory -v --json inv.json
```

### `vulns`: what is checked, and how confident the result is

| Component | Data source | Confidence label |
|---|---|---|
| Python packages (`--python-env`) | OSV.dev, PyPI advisories | **Confirmed**: the advisory lists this exact package version as affected |
| Linux distro packages | OSV.dev distro data (Ubuntu, Debian, AlmaLinux, Rocky), matched by *source* package and distro version, so fixes the distro backported into older versions are not flagged | **Confirmed** |
| Windows desktop apps on the curated list (`vulns/cpe_map.py`, about 30 common apps) | NVD CVE API, exact product and version (`cpeName` + `isVulnerable`) | **Likely** |
| Other desktop apps | not checked by default; `--fuzzy` guesses the NVD product name from the app name | **Needs verification** |
| Windows build (e.g. 25H2 26200.x) | NVD CPE data | **Needs verification**: Microsoft's Security Update Guide is the authoritative source, but its API is not in the approved list yet |

"Confidence" describes whether the installed version is listed as affected. It does not mean the flaw is exploitable on your PC.

Every CVE is enriched with **CISA KEV** (known exploited) and **FIRST EPSS** (probability of exploitation in the next 30 days). Results are ranked known-exploited first, then by EPSS, then by CVSS. Every finding includes:
- evidence: where the version was read (e.g. the exact registry key) and the API query
- the fixed version when the data lists one
- remediation and retest steps
- NVD and OSV links

Responses are cached for 24 hours (`[vulns] cache_ttl_hours`). `--offline` uses only the cache and warns when any of it has expired. If a data source fails entirely, the result says **Incomplete**, and with no findings the exit code is 2, never "clean".

*This product uses the NVD API but is not endorsed or certified by the NVD.*

### `audit`: read-only checks

The audit never changes a setting; it reports what to change. Checks needing admin rights report **"Skipped: requires admin"** instead of failing. Checks that don't apply to your edition report **n/a**, for example hosting Remote Desktop on Windows 11 Home.

| ID | Check | Unelevated? |
|---|---|---|
| WIN-FW-001 | Firewall on for Domain/Private/Public | yes |
| WIN-DEF-001/002/003 | Defender real-time protection, signature age ≤ 3 days, tamper protection | yes |
| WIN-SMB-001 | SMBv1 client/server not active | yes |
| WIN-RDP-001 | Remote Desktop off or NLA required (n/a on Home) | yes |
| WIN-UAC-001 | UAC on and prompting on the secure desktop | yes |
| WIN-ACC-001/002/003 | Guest disabled; no auto sign-in or stored password (the password itself is never read); everyday account is a standard user | yes |
| WIN-ENC-001 | BitLocker / Device encryption | **needs admin** |
| WIN-SB-001 | Secure Boot on | yes |
| WIN-VBS-001, WIN-LSA-001 | Memory integrity, LSA protection | yes |
| WIN-UPD-001/002/003 | Auto-updates not disabled by policy; no pending restart; an update installed in the last 45 days | yes |
| EXP-001 | Programs listening on non-loopback addresses (from the local socket table, not a network scan) | yes |
| PER-001 | Startup entries that run from user-writable folders (review list) | yes |
| LNX-*, MAC-* | Linux: firewall, SSH root/password login, automatic updates, NOPASSWD sudo, unowned SUID/SGID, world-writable system files, AppArmor/SELinux. macOS: FileVault, Gatekeeper, SIP, firewall, auto-updates | mostly |

Each check links to Microsoft Learn (or Ubuntu docs) plus the CIS Benchmark landing page. Every reference URL was checked to resolve on 2026-10-12.

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

## Architecture

```
src/hostguard/
  cli.py          argparse CLI, exit codes, progress display, top-level error handling
  config.py       TOML defaults + strict validation (unknown keys are errors)
  paths.py        per-user folders (platformdirs) and the scanner's self-exclusions
  logsetup.py     rotating log file + console; secret redaction filter
  credentials.py  API keys from env vars / keyring, never printed
  proc.py         the only subprocess entry point: list argv, no shell, timeouts, CWD-planting guard
  net.py          the only network entry point: HTTPS to approved hosts only, pacing, retries, cache, offline
  winsys.py       read-only registry access + constant PowerShell queries (JSON)
  sysinfo.py      OS / build / architecture / elevation
  models.py       Finding, Evidence, VulnInfo, Severity, Confidence, CheckStatus, ExitCode
  inventory/      windows.py, linux.py, macos.py, python_envs.py (metadata only), ports.py (psutil)
  vulns/          sources.py (OSV/NVD/KEV/EPSS), cpe_map.py, cvss.py, matcher.py (ranking, findings)
  audit/          base.py (framework), windows.py, linux.py, macos.py, common.py
  output.py       terminal tables and JSON (full reports arrive in Phase 5)
```

Network access is limited to these hosts (`net.APPROVED_HOSTS`): `services.nvd.nist.gov`, `api.osv.dev`, `www.cisa.gov`, `api.first.org`. Any other host is refused before a connection is opened, and redirects are not followed.

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

- **Windows code has not yet run on your PC.** It runs on GitHub's Windows runners (Windows Server 2025, as administrator) on every push. Windows 11 Home behaviour is covered by tests built from your PC's recon values. The first real unelevated run on Windows 11 Home is the remaining verification step.
- **Windows OS patch level** is matched via NVD's CPE data and labelled *Needs verification*. Exact build-to-update mapping needs Microsoft's Security Update Guide API (`api.msrc.microsoft.com`), which is not in the approved host list.
- **Desktop apps** are matched only if they are on the curated list (about 30 common apps). Apps from the Microsoft Store (MSIX/appx) are inventoried but rarely appear in NVD. `--fuzzy` widens coverage at the cost of false positives.
- **winget is not used.** `winget export` contacts Microsoft's package sources, which is network traffic outside the approved data sources. The registry Uninstall keys it reads are used directly.
- **Linux distro results** include many CVEs the distribution tracks but has not fixed yet. These are shown as "no fixed version listed". Kernel CVEs are only checked when a kernel image package is installed.
- **macOS** checks and inventory are written against Apple's documented tools but have not been run on a Mac.
- **CIS Benchmark section numbers** are not quoted, because the benchmark PDFs require registration. Each check links the benchmark landing page and the vendor's own guidance.
- Malware scanning, quarantine, updates and HTML reports are Phases 3 to 5.
