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
