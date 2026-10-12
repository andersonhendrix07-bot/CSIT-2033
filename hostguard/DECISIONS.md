# Design decisions

Short records of key choices and why they were made. Newest at the bottom.

1. **Built remotely, run on the user's Windows 11 PC.** Development happens in a Linux cloud container that has no access to the target PC. Windows-specific code is therefore written against documented APIs, unit-tested with mocks here, and verified on the real machine by the user. Each checkpoint lists exactly what has and hasn't run on Windows.

2. **`argparse`, not Typer/Click.** It's in the standard library, so a security tool needs one fewer dependency, and the CLI is simple enough without extras.

3. **Strict config validation.** Unknown keys and wrong types are errors. A typo such as `max_file_size_md = 5` must not quietly leave a safety limit at an unexpected value.

4. **One subprocess wrapper (`proc.py`).** List arguments only, `shell=False`, a closed stdin, a mandatory timeout, capped output with lossy decoding, and an absolute executable path. A match found only in the current directory is refused, because Windows `CreateProcess` searches the current directory before `PATH`, which allows binary planting. Returning the exact command line lets every finding cite it as evidence.

5. **Secrets come from env vars or keyring only, and are redacted at the log handler.** Every secret that is read is registered with a logging filter. Even an accidental log line containing a URL with `apiKey=` is written as `***`, including in tracebacks.

6. **Tests cannot reach the network.** An autouse fixture makes any IPv4/IPv6 `connect` raise, so all network code must be tested with mocks. Tests also never read the developer's real keyring.

7. **Findings without evidence cannot be built.** `Finding.__post_init__` raises when `evidence` is empty, which enforces the "no claim without evidence" rule in the type itself.

8. **Pinned dependencies via `uv.lock`.** It includes hashes for the whole dependency tree. Direct dependencies are also pinned exactly in `pyproject.toml`.

9. **Target is Windows 11 Home (build 26200), run unelevated, with Defender fully on.** This came from recon on the user's PC. As a result:
   - Pro-only features (BitLocker management, gpedit, the RDP host) are reported as "not applicable on Home", not as failures.
   - EICAR is only ever built in memory, because real-time protection would quarantine it on disk.
   - The edition is shown by its marketing name (`Core` → `Home`).

10. **Install path without git or uv.** The PC had neither. A hashed `requirements*.lock` exported from `uv.lock` gives pip the same pinned, hash-checked dependency tree. hatchling is in the lock (`build` group), so hostguard installs with `--no-build-isolation` and no unpinned build downloads. It is a regular install, not an editable one, because editable installs would need another build package.

11. **Network: one client, an allowlist, and pacing from the providers' docs.** `net.py` refuses non-HTTPS URLs, hosts outside the four approved data sources, credentials in URLs, odd ports and redirects. Pacing follows the documented limits:
    - NVD: 6 s between requests without a key, 0.6 s with one; the key goes in the `apiKey` header, never the URL.
    - FIRST: 1000 requests per minute.
    - OSV: no published limit, but requests are still paced.

    Responses are cached with timestamps. OSV results are cached **per package**, so a changed package list (or `--offline`) still reuses earlier answers.

12. **An incomplete scan is never "clean".** If a vulnerability source fails entirely, the result says *Incomplete*, and with no findings the exit code is 2. This was found when a cache miss in offline mode produced an empty, exit-0 result.

13. **Confidence describes the version match, not exploitability.**
    - *Confirmed*: an ecosystem or distro advisory lists the exact package version (OSV).
    - *Likely*: an NVD exact-product match through the curated CPE list.
    - *Needs verification*: fuzzy matching, and the Windows build via NVD.

14. **Curated CPE list instead of guessing.** Every `vendor:product` in `cpe_map.py` was confirmed to exist in NVD's CPE dictionary (2026-10-12). Guessing product names from display names produces false positives, so that is opt-in (`--fuzzy`). Each entry knows how to turn the registry's DisplayVersion into the product's public version. For example, the python.org installer reports `3.13.14150.0` for Python 3.13.14.

15. **Distro packages are matched by source package and distro version** (e.g. `openssl 3.0.13-0ubuntu3.16` in `Ubuntu:24.04:LTS`). Backported fixes are therefore recognised: the current Ubuntu `openssl` returns 0 advisories, while upstream `3.0.13` returns 54.
    - Advisories covering several CVEs (Ubuntu USNs) are applied to each CVE and merged with per-CVE records, so their fixed versions are not lost. A live cross-check against OSV found this bug.
    - Kernel source packages are only checked when a kernel image is installed. Header-only packages such as `linux-libc-dev` gave 3,769 irrelevant CVEs in testing.

16. **The Windows inventory reads the registry directly; winget is off.** The Uninstall keys (64-bit, WOW6432Node, HKCU) are what winget itself lists. `winget export` would contact Microsoft's package sources, which is outside the approved network scope.

17. **The audit is read-only, and secrets stay unread.** The auto-logon check lists value *names* under Winlogon, so a stored `DefaultPassword` is detected without its contents ever being read. A test asserts this. PowerShell is only called with constant scripts, and nothing from the system is interpolated into them.

18. **Python environments are inventoried from metadata files only.** The environment's interpreter is never run, and `.pth` files are never processed, so a malicious package cannot execute during inventory.
