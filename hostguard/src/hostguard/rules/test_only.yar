// Test-only rule, loaded only when explicitly enabled (tests, quarantine self-test).
// It matches a harmless marker string so quarantine can be exercised without EICAR.

rule HostGuard_Test_Marker
{
    meta:
        description = "hostguard test-only marker (harmless)"
        author = "hostguard"
        confidence = "high"
        test = true
    strings:
        $m = "HOSTGUARD-TEST-ONLY-MARKER-7f3c9a1e"
    condition:
        $m
}
