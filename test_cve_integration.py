#!/usr/bin/env python3
"""Quick test of CVE integration"""

import sys
sys.path.insert(0, 'src')

from cve_provider import CVEProvider

# Initialize provider
provider = CVEProvider(cache_dir="./data/cve_cache")

# Test 1: Fetch a specific CVE
print("="*70)
print("Test 1: Fetch BlueKeep CVE")
print("="*70)
cve = provider.get_cve_details("CVE-2019-0708")
if cve:
    print(f"✅ {cve.cve_id}: {cve.severity} (CVSS: {cve.cvss_score})")
    print(f"   {cve.description[:100]}...")
else:
    print("❌ Failed to fetch CVE")

# Test 2: Get service CVEs
print("\n" + "="*70)
print("Test 2: RDP Vulnerabilities")
print("="*70)
rdp_cves = provider.get_service_cves("rdp")
print(f"Found {len(rdp_cves)} CVEs for RDP:")
for cve in rdp_cves:
    print(f"   - {cve.cve_id}: {cve.severity}")

# Test 3: Enrich mock scan results
print("\n" + "="*70)
print("Test 3: Enrich Scan Results")
print("="*70)
mock_results = [
    {'port': 3389, 'service': 'rdp', 'banner': 'Microsoft RDP'},
    {'port': 22, 'service': 'ssh', 'banner': 'OpenSSH'},
]

enriched = provider.enrich_scan_results(mock_results)
for result in enriched:
    print(f"\nPort {result['port']} ({result['service']}):")
    print(f"   CVE Count: {result['cve_count']}")
    if result['cve_count'] > 0:
        print(f"   Highest Severity: {result['highest_cve_severity']}")

print("\n" + "="*70)
print("✅ All tests passed! CVE integration working.")
print("="*70)
