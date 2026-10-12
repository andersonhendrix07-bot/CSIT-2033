"""Windows configuration checks (read-only, designed to run unelevated).

Registry paths and value semantics follow the Microsoft Learn pages cited on
each check. CIS reference: CIS Microsoft Windows 11 benchmarks (landing page
linked; the benchmark PDFs require registration, so section numbers are not
quoted here).
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from hostguard.audit.base import (
    REQUIRES_ADMIN,
    AuditContext,
    Outcome,
    check,
    failed,
    not_applicable,
    passed,
    skipped,
)
from hostguard.models import Confidence, Evidence, Severity
from hostguard.winsys import HKLM, PowerShellError, iter_dicts, reg_evidence

CIS_WIN = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"
MS = "https://learn.microsoft.com/en-us"

PS_FIREWALL = "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
PS_DEFENDER = (
    "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,"
    "IsTamperProtected,AntivirusSignatureAge,AntivirusSignatureLastUpdated,AMRunningMode,AMProductVersion"
    " | ConvertTo-Json -Compress"
)
PS_AV_PRODUCTS = (
    "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
    "Select-Object displayName,productState | ConvertTo-Json -Compress"
)
PS_LOCAL_USERS = "Get-LocalUser | Select-Object Name,Enabled,@{n='SID';e={$_.SID.Value}} | ConvertTo-Json -Compress"
PS_WHOAMI = (
    "$id=[Security.Principal.WindowsIdentity]::GetCurrent();"
    "[pscustomobject]@{User=$id.Name;"
    "AdminGroupMember=[bool]($id.Groups | Where-Object { $_.Value -eq 'S-1-5-32-544' })}"
    " | ConvertTo-Json -Compress"
)
PS_BITLOCKER = (
    "Get-BitLockerVolume -MountPoint $env:SystemDrive | "
    "Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage | ConvertTo-Json -Compress"
)
PS_HOTFIX = (
    "Get-HotFix | Select-Object HotFixID,"
    "@{n='InstalledOn';e={if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}}}"
    " | ConvertTo-Json -Compress"
)

SIGNATURE_MAX_AGE_DAYS = 3
UPDATE_MAX_AGE_DAYS = 45


def _true(v: object) -> bool:
    return str(v).strip().lower() in ("true", "1")


def _is_home(ctx: AuditContext) -> bool:
    return ctx.edition_id.startswith("Core")


# --- Firewall and Defender -------------------------------------------------------------


@check(
    "WIN-FW-001",
    "Windows Firewall enabled for all network profiles",
    family="windows",
    severity=Severity.HIGH,
    remediation="Open Windows Security > Firewall & network protection and turn on the firewall for "
    "Domain, Private and Public networks.",
    references=(
        f"{MS}/windows/security/operating-system-security/network-security/windows-firewall/",
        CIS_WIN,
    ),
    retest="Run `hostguard audit`; WIN-FW-001 should pass with all three profiles Enabled.",
)
def firewall(ctx: AuditContext) -> Outcome:
    data, ev = ctx.ps(PS_FIREWALL)
    profiles = {str(d.get("Name")): _true(d.get("Enabled")) for d in iter_dicts(data)}
    if not profiles:
        return failed(
            "no firewall profiles were returned", ev, confidence=Confidence.NEEDS_VERIFICATION
        )
    off = sorted(n for n, on in profiles.items() if not on)
    if off:
        return failed(f"firewall is off for: {', '.join(off)}", ev)
    return passed(f"enabled for {', '.join(sorted(profiles))}", ev)


def _defender(ctx: AuditContext) -> tuple[dict[str, object] | None, Evidence | None, str]:
    try:
        data, ev = ctx.ps(PS_DEFENDER)
    except PowerShellError as exc:
        return None, exc.evidence, str(exc)
    items = list(iter_dicts(data))
    return (items[0] if items else None), ev, ""


def _third_party_av(ctx: AuditContext) -> tuple[list[str], Evidence | None]:
    try:
        data, ev = ctx.ps(PS_AV_PRODUCTS)
    except PowerShellError:
        return [], None
    names = [str(d.get("displayName")) for d in iter_dicts(data)]
    return [n for n in names if "defender" not in n.lower()], ev


@check(
    "WIN-DEF-001",
    "Microsoft Defender real-time protection on",
    family="windows",
    severity=Severity.HIGH,
    remediation="Open Windows Security > Virus & threat protection > Manage settings and turn on "
    "Real-time protection. If another antivirus is installed, make sure it is active instead.",
    references=(
        f"{MS}/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus",
        CIS_WIN,
    ),
    retest="Run `hostguard audit`; WIN-DEF-001 should pass (RealTimeProtectionEnabled = True).",
)
def defender_rtp(ctx: AuditContext) -> Outcome:
    st, ev, err = _defender(ctx)
    others, ev2 = _third_party_av(ctx)
    evs = [e for e in (ev, ev2) if e]
    if st is None:
        if others:
            return not_applicable(
                f"Defender not reporting; other antivirus registered: {', '.join(others)}", *evs
            )
        return failed(
            f"could not read Defender status ({err}) and no other antivirus is registered",
            *evs,
            confidence=Confidence.NEEDS_VERIFICATION,
        )
    mode = str(st.get("AMRunningMode") or "")
    if "passive" in mode.lower() and others:
        return not_applicable(f"Defender is in {mode}; active antivirus: {', '.join(others)}", *evs)
    if _true(st.get("RealTimeProtectionEnabled")) and _true(st.get("AMServiceEnabled")):
        return passed("real-time protection is on", *evs)
    return failed(
        f"RealTimeProtectionEnabled={st.get('RealTimeProtectionEnabled')}, AMServiceEnabled={st.get('AMServiceEnabled')}",
        *evs,
    )


@check(
    "WIN-DEF-002",
    f"Defender security intelligence updated within {SIGNATURE_MAX_AGE_DAYS} days",
    family="windows",
    severity=Severity.MEDIUM,
    remediation="Open Windows Security > Virus & threat protection > Protection updates and select "
    "'Check for updates'. Make sure Windows Update is not paused.",
    references=(f"{MS}/defender-endpoint/microsoft-defender-antivirus-updates",),
    retest="Run `hostguard audit`; WIN-DEF-002 should pass (AntivirusSignatureAge 0-3 days).",
)
def defender_signatures(ctx: AuditContext) -> Outcome:
    st, ev, err = _defender(ctx)
    if st is None:
        return skipped(f"Defender status unavailable: {err}", *([ev] if ev else []))
    age = st.get("AntivirusSignatureAge")
    if not isinstance(age, int):
        return skipped("AntivirusSignatureAge not reported", *([ev] if ev else []))
    if age > SIGNATURE_MAX_AGE_DAYS:
        sev = Severity.HIGH if age > 14 else Severity.MEDIUM
        return failed(f"signatures are {age} days old", *([ev] if ev else []), severity=sev)
    return passed(f"signatures are {age} day(s) old", *([ev] if ev else []))


@check(
    "WIN-DEF-003",
    "Defender tamper protection on",
    family="windows",
    severity=Severity.MEDIUM,
    remediation="Open Windows Security > Virus & threat protection > Manage settings and turn on Tamper Protection.",
    references=(
        f"{MS}/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection",
    ),
    retest="Run `hostguard audit`; WIN-DEF-003 should pass (IsTamperProtected = True).",
)
def defender_tamper(ctx: AuditContext) -> Outcome:
    st, ev, err = _defender(ctx)
    evs = [ev] if ev else []
    if st is None:
        return skipped(f"Defender status unavailable: {err}", *evs)
    if _true(st.get("IsTamperProtected")):
        return passed("tamper protection is on", *evs)
    return failed("tamper protection is off", *evs)


# --- Network services -----------------------------------------------------------------------

SERVICES = r"SYSTEM\CurrentControlSet\Services"


@check(
    "WIN-SMB-001",
    "SMBv1 disabled",
    family="windows",
    severity=Severity.HIGH,
    remediation="Turn off SMB 1.0/CIFS: open 'Turn Windows features on or off', clear 'SMB 1.0/CIFS File "
    "Sharing Support' and restart (or follow the Microsoft Learn steps).",
    references=(
        f"{MS}/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
        CIS_WIN,
    ),
    retest="Run `hostguard audit`; WIN-SMB-001 should pass (no enabled mrxsmb10 / SMB1 server driver).",
)
def smb1(ctx: AuditContext) -> Outcome:
    problems, evs = [], []
    client = ctx.reg.values(HKLM, f"{SERVICES}\\mrxsmb10")
    if client is not None:
        evs.append(reg_evidence(HKLM, f"{SERVICES}\\mrxsmb10", {"Start": client.get("Start")}))
        if client.get("Start") != 4:
            problems.append("SMB1 client driver (mrxsmb10) is installed and not disabled")
    else:
        evs.append(
            reg_evidence(
                HKLM, f"{SERVICES}\\mrxsmb10", "key not present (SMB1 client not installed)"
            )
        )
    params = f"{SERVICES}\\LanmanServer\\Parameters"
    smb1_server = ctx.reg.value(HKLM, params, "SMB1")
    srv = ctx.reg.values(HKLM, f"{SERVICES}\\srv")
    evs.append(reg_evidence(HKLM, params, {"SMB1": smb1_server}))
    if srv is not None and srv.get("Start") != 4 and smb1_server != 0:
        evs.append(reg_evidence(HKLM, f"{SERVICES}\\srv", {"Start": srv.get("Start")}))
        problems.append("SMB1 server driver (srv) is installed and SMB1 is not set to 0")
    if problems:
        return failed("; ".join(problems), *evs, confidence=Confidence.LIKELY)
    return passed("SMB1 client and server components are not active", *evs)


TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"


@check(
    "WIN-RDP-001",
    "Remote Desktop off, or Network Level Authentication required",
    family="windows",
    severity=Severity.HIGH,
    remediation="If you do not use Remote Desktop, turn it off in Settings > System > Remote Desktop. "
    "If you need it, keep 'Require devices to use Network Level Authentication' on.",
    references=(
        f"{MS}/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access",
        CIS_WIN,
    ),
    retest="Run `hostguard audit`; WIN-RDP-001 should pass (fDenyTSConnections = 1, or UserAuthentication = 1).",
)
def rdp(ctx: AuditContext) -> Outcome:
    if _is_home(ctx):
        return not_applicable("Windows 11 Home cannot host incoming Remote Desktop connections")
    deny = ctx.reg.value(HKLM, TS, "fDenyTSConnections")
    nla = ctx.reg.value(HKLM, f"{TS}\\WinStations\\RDP-Tcp", "UserAuthentication")
    ev = reg_evidence(HKLM, TS, {"fDenyTSConnections": deny, "RDP-Tcp\\UserAuthentication": nla})
    if deny == 1:
        return passed("Remote Desktop is off", ev)
    if nla == 1:
        return passed("Remote Desktop is on with Network Level Authentication required", ev)
    return failed("Remote Desktop is on without Network Level Authentication", ev)


# --- Accounts and sign-in -----------------------------------------------------------------------

UAC = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


@check(
    "WIN-UAC-001",
    "User Account Control enabled and prompting",
    family="windows",
    severity=Severity.HIGH,
    remediation="Open 'Change User Account Control settings' and set the slider to at least the default "
    "('Notify me only when apps try to make changes'), then restart.",
    references=(
        f"{MS}/windows/security/application-security/application-control/user-account-control/settings-and-configuration",
        CIS_WIN,
    ),
    retest="Run `hostguard audit`; WIN-UAC-001 should pass (EnableLUA = 1, ConsentPromptBehaviorAdmin != 0, PromptOnSecureDesktop = 1).",
)
def uac(ctx: AuditContext) -> Outcome:
    v = ctx.reg.values(HKLM, UAC) or {}
    # Documented defaults when a value is absent: EnableLUA=1, ConsentPromptBehaviorAdmin=5, PromptOnSecureDesktop=1.
    lua = v.get("EnableLUA", 1)
    cpba = v.get("ConsentPromptBehaviorAdmin", 5)
    posd = v.get("PromptOnSecureDesktop", 1)
    ev = reg_evidence(
        HKLM,
        UAC,
        {"EnableLUA": lua, "ConsentPromptBehaviorAdmin": cpba, "PromptOnSecureDesktop": posd},
    )
    if lua == 0:
        return failed("UAC is disabled (EnableLUA = 0)", ev, severity=Severity.HIGH)
    if cpba == 0:
        return failed(
            "administrators are elevated without any prompt (ConsentPromptBehaviorAdmin = 0)", ev
        )
    if posd == 0:
        return failed(
            "UAC prompts are not shown on the secure desktop", ev, severity=Severity.MEDIUM
        )
    return passed("UAC is on and prompts on the secure desktop", ev)


@check(
    "WIN-ACC-001",
    "Guest account disabled",
    family="windows",
    severity=Severity.MEDIUM,
    remediation="Disable the built-in Guest account (from an administrator PowerShell: "
    "Disable-LocalUser -SID (Get-LocalUser | Where-Object { $_.SID -like '*-501' }).SID).",
    references=(
        f"{MS}/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-guest-account-status",
        CIS_WIN,
    ),
    retest="Run `hostguard audit`; WIN-ACC-001 should pass (account with RID 501 Enabled = False).",
)
def guest(ctx: AuditContext) -> Outcome:
    data, ev = ctx.ps(PS_LOCAL_USERS)
    for u in iter_dicts(data):
        if str(u.get("SID", "")).endswith("-501"):  # well-known RID of the Guest account
            if _true(u.get("Enabled")):
                return failed(f"the Guest account ({u.get('Name')}) is enabled", ev)
            return passed(f"the Guest account ({u.get('Name')}) is disabled", ev)
    return passed("no Guest account found", ev)


WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


@check(
    "WIN-ACC-002",
    "Automatic sign-in disabled and no stored password",
    family="windows",
    severity=Severity.HIGH,
    remediation="Turn off automatic sign-in (Settings > Accounts > Sign-in options) and remove the stored "
    "DefaultPassword value from the Winlogon registry key, as described by Microsoft.",
    references=(
        f"{MS}/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon",
        CIS_WIN,
    ),
    retest="Run `hostguard audit`; WIN-ACC-002 should pass (AutoAdminLogon != 1 and no DefaultPassword value).",
)
def autologon(ctx: AuditContext) -> Outcome:
    # Only value *names* are listed so the stored password itself is never read.
    names = ctx.reg.value_names(HKLM, WINLOGON) or []
    auto = ctx.reg.value(HKLM, WINLOGON, "AutoAdminLogon")
    has_pw = "DefaultPassword" in names
    ev = reg_evidence(
        HKLM,
        WINLOGON,
        f"AutoAdminLogon={auto!r}; DefaultPassword value {'PRESENT (contents not read)' if has_pw else 'absent'}",
    )
    if has_pw:
        return failed(
            "a sign-in password is stored in plain text in the registry (DefaultPassword)", ev
        )
    if str(auto) == "1":
        return failed("automatic sign-in is enabled", ev, severity=Severity.MEDIUM)
    return passed("automatic sign-in is off", ev)


@check(
    "WIN-ACC-003",
    "Day-to-day account is a standard user",
    family="windows",
    severity=Severity.LOW,
    remediation="Create a separate administrator account for installs and system changes, and change your "
    "everyday account to a Standard user (Settings > Accounts > Other users).",
    references=(
        f"{MS}/windows/security/identity-protection/access-control/local-accounts",
        CIS_WIN,
    ),
    retest="Sign in with your everyday account and run `hostguard audit`; WIN-ACC-003 should pass.",
)
def daily_admin(ctx: AuditContext) -> Outcome:
    data, ev = ctx.ps(PS_WHOAMI)
    items = list(iter_dicts(data))
    if not items:
        return skipped("could not determine the current user's groups", ev)
    me = items[0]
    if _true(me.get("AdminGroupMember")):
        return failed(f"{me.get('User')} is a member of the local Administrators group", ev)
    return passed(f"{me.get('User')} is a standard user", ev)


# --- Platform protection -----------------------------------------------------------------------------


@check(
    "WIN-ENC-001",
    "System drive encrypted (BitLocker / Device encryption)",
    family="windows",
    severity=Severity.MEDIUM,
    remediation="Turn on Device encryption (Windows 11 Home: Settings > Privacy & security > Device encryption) "
    "or BitLocker (Pro and above). Back up the recovery key first.",
    references=(
        f"{MS}/windows/security/operating-system-security/data-protection/bitlocker/",
        CIS_WIN,
    ),
    retest="Run `hostguard audit` from an administrator terminal; WIN-ENC-001 should pass (ProtectionStatus On).",
)
def encryption(ctx: AuditContext) -> Outcome:
    if not ctx.elevated:
        return skipped(
            f"{REQUIRES_ADMIN} (BitLocker status is only readable by administrators). "
            "Check manually: Settings > Privacy & security > Device encryption."
        )
    data, ev = ctx.ps(PS_BITLOCKER)
    vols = list(iter_dicts(data))
    if not vols:
        return skipped("no BitLocker information returned", ev)
    v = vols[0]
    status = _VOLUME_STATUS.get(str(v.get("VolumeStatus")), str(v.get("VolumeStatus")))
    if str(v.get("ProtectionStatus")).lower() in ("on", "1"):
        return passed(f"{v.get('MountPoint')} protection is on ({status})", ev)
    return failed(f"{v.get('MountPoint')} is not protected ({status})", ev)


# Windows PowerShell 5.1 serialises these enums as numbers (seen on a real Windows runner).
_VOLUME_STATUS = {
    "0": "FullyDecrypted",
    "1": "FullyEncrypted",
    "2": "EncryptionInProgress",
    "3": "DecryptionInProgress",
    "4": "EncryptionPaused",
    "5": "DecryptionPaused",
}


SECUREBOOT = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"


@check(
    "WIN-SB-001",
    "Secure Boot enabled",
    family="windows",
    severity=Severity.MEDIUM,
    remediation="Enable Secure Boot in your PC's UEFI firmware settings (see the PC maker's instructions). "
    "Windows 11 devices normally ship with it on.",
    references=(f"{MS}/windows-hardware/design/device-experiences/oem-secure-boot", CIS_WIN),
    retest="Run `hostguard audit`; WIN-SB-001 should pass (UEFISecureBootEnabled = 1).",
)
def secure_boot(ctx: AuditContext) -> Outcome:
    v = ctx.reg.value(HKLM, SECUREBOOT, "UEFISecureBootEnabled")
    ev = reg_evidence(HKLM, SECUREBOOT, {"UEFISecureBootEnabled": v})
    if v == 1:
        return passed("Secure Boot is on", ev)
    if v is None:
        return failed(
            "Secure Boot state not reported (legacy BIOS or unsupported firmware)",
            ev,
            confidence=Confidence.LIKELY,
        )
    return failed("Secure Boot is off", ev)


DEVICEGUARD = (
    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
)


@check(
    "WIN-VBS-001",
    "Memory integrity (HVCI) enabled",
    family="windows",
    severity=Severity.LOW,
    remediation="Open Windows Security > Device security > Core isolation details and turn on Memory integrity "
    "(restart required; incompatible drivers are listed there).",
    references=(
        f"{MS}/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity",
    ),
    retest="Run `hostguard audit`; WIN-VBS-001 should pass (HypervisorEnforcedCodeIntegrity Enabled = 1).",
)
def hvci(ctx: AuditContext) -> Outcome:
    v = ctx.reg.value(HKLM, DEVICEGUARD, "Enabled")
    ev = reg_evidence(HKLM, DEVICEGUARD, {"Enabled": v})
    if v == 1:
        return passed("memory integrity is configured on", ev)
    return failed("memory integrity is off or not configured", ev, confidence=Confidence.LIKELY)


LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"


@check(
    "WIN-LSA-001",
    "LSA protection enabled",
    family="windows",
    severity=Severity.LOW,
    remediation="Open Windows Security > Device security > Core isolation details and turn on "
    "'Local Security Authority protection', then restart.",
    references=(
        f"{MS}/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection",
    ),
    retest="Run `hostguard audit`; WIN-LSA-001 should pass (RunAsPPL = 1 or 2).",
)
def lsa(ctx: AuditContext) -> Outcome:
    v = ctx.reg.value(HKLM, LSA, "RunAsPPL")
    ev = reg_evidence(HKLM, LSA, {"RunAsPPL": v})
    if v in (1, 2):
        return passed(f"LSA protection is configured (RunAsPPL = {v})", ev)
    if v is None:
        return failed(
            "RunAsPPL is not set; LSA protection may be off",
            ev,
            confidence=Confidence.NEEDS_VERIFICATION,
        )
    return failed(f"LSA protection is off (RunAsPPL = {v})", ev)


# --- Updates -----------------------------------------------------------------------------------------

AU_POLICY = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"


@check(
    "WIN-UPD-001",
    "Automatic updates not disabled by policy",
    family="windows",
    severity=Severity.HIGH,
    remediation="Remove the policy that disables automatic updates (NoAutoUpdate under the WindowsUpdate\\AU "
    "policy key, usually set by a 'tweak' tool), then check Settings > Windows Update.",
    references=(f"{MS}/windows/deployment/update/waas-wu-settings", CIS_WIN),
    retest="Run `hostguard audit`; WIN-UPD-001 should pass (NoAutoUpdate absent or 0).",
)
def auto_updates(ctx: AuditContext) -> Outcome:
    v = ctx.reg.values(HKLM, AU_POLICY)
    ev = reg_evidence(
        HKLM,
        AU_POLICY,
        v if v is not None else "policy key not present (default: automatic updates on)",
    )
    if v and v.get("NoAutoUpdate") == 1:
        return failed("automatic updates are disabled by policy (NoAutoUpdate = 1)", ev)
    if v and v.get("AUOptions") == 1:
        return failed("automatic updates are set to never check (AUOptions = 1)", ev)
    return passed("automatic updates are not disabled by policy", ev)


REBOOT_KEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
)


@check(
    "WIN-UPD-002",
    "No restart pending to finish installing updates",
    family="windows",
    severity=Severity.LOW,
    remediation="Save your work and restart Windows so installed updates take effect.",
    references=(f"{MS}/windows/deployment/update/waas-restart",),
    retest="After restarting, run `hostguard audit`; WIN-UPD-002 should pass.",
)
def reboot_pending(ctx: AuditContext) -> Outcome:
    present = [k for k in REBOOT_KEYS if ctx.reg.values(HKLM, k) is not None]
    ev = reg_evidence(
        HKLM, " | ".join(REBOOT_KEYS), {k.rsplit("\\", 1)[1]: (k in present) for k in REBOOT_KEYS}
    )
    if present:
        return failed("a restart is pending to complete updates", ev)
    return passed("no update restart pending", ev)


@check(
    "WIN-UPD-003",
    f"Windows updates installed within the last {UPDATE_MAX_AGE_DAYS} days",
    family="windows",
    severity=Severity.MEDIUM,
    remediation="Open Settings > Windows Update, select 'Check for updates', install everything offered and restart.",
    references=(f"{MS}/windows/deployment/update/waas-wu-settings",),
    retest="Run `hostguard audit`; WIN-UPD-003 should show the newest update installed recently.",
)
def recent_updates(ctx: AuditContext) -> Outcome:
    data, ev = ctx.ps(PS_HOTFIX)
    dates = []
    for d in iter_dicts(data):
        try:
            dates.append(date.fromisoformat(str(d.get("InstalledOn"))))
        except ValueError:
            continue
    if not dates:
        return skipped("no installation dates reported by Get-HotFix", ev)
    newest = max(dates)
    age = (datetime.now(UTC).date() - newest).days
    if age > UPDATE_MAX_AGE_DAYS:
        return failed(
            f"newest update was installed {age} days ago ({newest})",
            ev,
            confidence=Confidence.LIKELY,
        )
    return passed(f"newest update installed {newest} ({age} days ago)", ev)
