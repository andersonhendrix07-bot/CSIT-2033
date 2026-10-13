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

19. **oletools without its GPL and crypto extras.** `oletools` declares `pcodedmp` (GPL, only used for P-code disassembly) and `msoffcrypto-tool` (decrypting Office files; pulls in `cryptography`). olevba imports both lazily and works without them, so `uv.lock` excludes them via `override-dependencies`, and pip installs use `--no-deps` from the hashed lock. `pip check` therefore lists them as missing; that is intended.

20. **YARA-X, not libyara, and no pefile.** YARA-X is written in Rust, so parsing hostile files is memory-safe. Its `pe` module provides sections, imports and signatures for the PE heuristics, which removes a dependency. Both chosen rule sets compile without errors (ReversingLabs: 1,240 rules; signature-base: 5,904 rules, using `relaxed_re_syntax` and the LOKI external variables `filename`, `filepath`, `extension`, `filetype` and `owner`). Compiled rules are cached (9.6 MB; reload in about 2.5 s instead of compiling in about 7 s).

21. **YARA match confidence and attribution.**
    - ReversingLabs rules are malware-family rules, so every match is high-confidence (Malicious).
    - signature-base rules carry a `score`; matches at 75 or above are high-confidence, lower scores are Suspicious.
    - Unknown sets default to low confidence.
    - Every match keeps the rule's author and reference and the set's licence, as the Detection Rule License 1.1 requires.

22. **Code-signature trust needs OS chain validation.** YARA-X's `verified` flag only shows that a signature is internally consistent; a self-signed certificate claiming "O=Microsoft Corporation" also passes it. The allowlist therefore trusts only `Get-AuthenticodeSignature` Status = Valid (which validates the chain and handles catalog signatures) together with a trusted publisher name. File paths go to PowerShell on stdin as JSON, never inside the script. On non-Windows systems, PE signatures are shown but never trusted. Linux files are trusted only if dpkg's MD5 for them still matches.

23. **Processes, not threads, for scanning.** Measurements showed 4 threads were no faster than 1 (YARA-X holds the GIL). The scanner uses a spawn-based process pool, so the start method is the same on every OS. If worker processes cannot start, the scan falls back to the main process and says so, rather than reporting every file as an error. Only flagged, skipped and error results are kept in memory.

24. **EICAR never touches hostguard's files.** Defender treats the EICAR string as malware, so:
    - the built-in rule matches it as hex bytes;
    - the self-test rebuilds it in memory from an XOR-encoded constant;
    - a test scans the source and test trees, including `.pyc` files, for EICAR fragments. That test caught Python constant-folding two halves of a search string into one `.pyc` constant.

    On-disk EICAR tests run only in a pytest temp folder and are skipped if antivirus blocks them.

25. **ClamAV stays local and optional.** hostguard never installs ClamAV. Only Unix sockets or loopback TCP addresses are accepted for clamd. `clamscan` runs once per scan with `--file-list` (built while walking), so hostile file names are never parsed as command-line options and the signature database loads only once.

26. **VirusTotal is evidence, not a verdict.** It is off by default and only looks up hashes of files the local engines already flagged, up to 20 per run, respecting the documented public-API limits (4/min, 500/day, non-commercial). Files are never uploaded. Its result is shown next to the local verdict and never changes it.
