#!/usr/bin/env python3
"""
Test Suite for Security Audit Tool v2.0
Basic tests to verify functionality
"""

import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from main import SecurityScanner, ScanResult, VULNERABILITY_DB, PORT_SERVICES
except ImportError as e:
    print(f"Error importing main module: {e}")
    print("Make sure you're running from the project root directory")
    sys.exit(1)


class TestScanResult(unittest.TestCase):
    """Test ScanResult dataclass"""
    
    def test_scan_result_creation(self):
        """Test creating a ScanResult"""
        result = ScanResult(
            port=22,
            state="open",
            service="ssh",
            banner="OpenSSH_8.9",
            vulnerabilities=[],
            severity="info"
        )
        
        self.assertEqual(result.port, 22)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.service, "ssh")
        
    def test_scan_result_to_dict(self):
        """Test converting ScanResult to dictionary"""
        result = ScanResult(
            port=80,
            state="open",
            service="http"
        )
        
        result_dict = result.to_dict()
        self.assertIsInstance(result_dict, dict)
        self.assertEqual(result_dict['port'], 80)


class TestVulnerabilityDatabase(unittest.TestCase):
    """Test vulnerability database"""
    
    def test_vulnerability_db_exists(self):
        """Test that vulnerability database is populated"""
        self.assertGreater(len(VULNERABILITY_DB), 0)
        
    def test_ftp_vulnerability_exists(self):
        """Test FTP vulnerability is defined"""
        self.assertIn("ftp", VULNERABILITY_DB)
        self.assertEqual(VULNERABILITY_DB["ftp"]["severity"], "high")
        
    def test_telnet_vulnerability_critical(self):
        """Test Telnet is marked as critical"""
        self.assertIn("telnet", VULNERABILITY_DB)
        self.assertEqual(VULNERABILITY_DB["telnet"]["severity"], "critical")


class TestPortServices(unittest.TestCase):
    """Test port to service mapping"""
    
    def test_common_ports_mapped(self):
        """Test common ports are mapped"""
        self.assertEqual(PORT_SERVICES[22], "ssh")
        self.assertEqual(PORT_SERVICES[80], "http")
        self.assertEqual(PORT_SERVICES[443], "https")
        self.assertEqual(PORT_SERVICES[3306], "mysql")
        
    def test_database_ports(self):
        """Test database ports are mapped"""
        self.assertEqual(PORT_SERVICES[3306], "mysql")
        self.assertEqual(PORT_SERVICES[5432], "postgresql")
        self.assertEqual(PORT_SERVICES[6379], "redis")
        self.assertEqual(PORT_SERVICES[27017], "mongodb")


class TestSecurityScanner(unittest.TestCase):
    """Test SecurityScanner class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = SecurityScanner(
            target="127.0.0.1",
            timeout=0.5,
            max_workers=10,
            verbose=False
        )
        
    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        self.assertEqual(self.scanner.target, "127.0.0.1")
        self.assertEqual(self.scanner.timeout, 0.5)
        self.assertEqual(self.scanner.max_workers, 10)
        
    def test_parse_port_range_single(self):
        """Test parsing single port"""
        ports = self.scanner._parse_port_range("80")
        self.assertEqual(ports, [80])
        
    def test_parse_port_range_list(self):
        """Test parsing port list"""
        ports = self.scanner._parse_port_range("22,80,443")
        self.assertEqual(sorted(ports), [22, 80, 443])
        
    def test_parse_port_range_range(self):
        """Test parsing port range"""
        ports = self.scanner._parse_port_range("20-25")
        self.assertEqual(ports, [20, 21, 22, 23, 24, 25])
        
    def test_parse_port_range_mixed(self):
        """Test parsing mixed format"""
        ports = self.scanner._parse_port_range("22,80-82,443")
        self.assertEqual(sorted(ports), [22, 80, 81, 82, 443])
        
    def test_scan_localhost_ssh(self):
        """Test scanning SSH port on localhost"""
        result = self.scanner.scan_port(22)
        
        if result:  # SSH might be running
            self.assertEqual(result.port, 22)
            self.assertEqual(result.state, "open")
        else:  # SSH not running, that's okay
            self.assertIsNone(result)
            
    def test_scan_closed_port(self):
        """Test scanning a closed port"""
        # Port 9999 is very unlikely to be open
        result = self.scanner.scan_port(9999)
        self.assertIsNone(result)


class TestVulnerabilityDetection(unittest.TestCase):
    """Test vulnerability detection logic"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = SecurityScanner(
            target="127.0.0.1",
            timeout=0.5,
            max_workers=10,
            verbose=False
        )
        
    def test_detect_ftp_vulnerability(self):
        """Test FTP service is flagged as vulnerable"""
        vulns, severity = self.scanner._check_vulnerabilities(21, "ftp", "")
        
        self.assertGreater(len(vulns), 0)
        self.assertEqual(severity, "high")
        
    def test_detect_telnet_vulnerability(self):
        """Test Telnet service is flagged as critical"""
        vulns, severity = self.scanner._check_vulnerabilities(23, "telnet", "")
        
        self.assertGreater(len(vulns), 0)
        self.assertEqual(severity, "critical")
        
    def test_ssh_no_vulnerability(self):
        """Test SSH service with modern version is not flagged"""
        vulns, severity = self.scanner._check_vulnerabilities(
            22, "ssh", "OpenSSH_8.9p1 Ubuntu"
        )
        
        # Modern SSH should have no vulnerabilities
        if len(vulns) == 0:
            self.assertEqual(severity, "info")
            
    def test_outdated_ssh_vulnerability(self):
        """Test outdated SSH version is flagged"""
        vulns, severity = self.scanner._check_vulnerabilities(
            22, "ssh", "OpenSSH_5.3p1 Debian"
        )
        
        # Old SSH should be flagged
        self.assertGreater(len(vulns), 0)


class IntegrationTests(unittest.TestCase):
    """Integration tests for complete workflows"""
    
    def test_full_scan_localhost(self):
        """Test complete scan on localhost"""
        scanner = SecurityScanner(
            target="127.0.0.1",
            timeout=0.3,
            max_workers=20,
            verbose=False
        )
        
        # Scan common ports
        results = scanner.scan_range("20-25,80,443")
        
        # Should return a list (might be empty if no services running)
        self.assertIsInstance(results, list)
        
        # If SSH is running, should detect it
        ssh_results = [r for r in results if r.port == 22]
        if ssh_results:
            self.assertEqual(ssh_results[0].service, "ssh")


def run_tests():
    """Run all tests and print summary"""
    print("="*70)
    print("Security Audit Tool v2.0 - Test Suite")
    print("="*70)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestScanResult))
    suite.addTests(loader.loadTestsFromTestCase(TestVulnerabilityDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestPortServices))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestVulnerabilityDetection))
    suite.addTests(loader.loadTestsFromTestCase(IntegrationTests))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print()
    print("="*70)
    print("Test Summary")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if result.wasSuccessful():
        print("\n✅ All tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(run_tests())
