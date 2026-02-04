#!/usr/bin/env python3
"""
Test Suite for CVE Provider Module
Tests CVE data fetching, caching, and enrichment functionality
"""

import unittest
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cve_provider import CVEProvider, CVEDetails


class TestCVEDetails(unittest.TestCase):
    """Test CVEDetails dataclass"""
    
    def test_cve_details_creation(self):
        """Test creating CVEDetails object"""
        cve = CVEDetails(
            cve_id="CVE-2023-12345",
            description="Test vulnerability",
            cvss_score=7.5,
            severity="HIGH",
            published_date="2023-01-01",
            last_modified="2023-01-02",
            affected_products=["product:1.0"],
            references=["https://example.com"],
            cwe_ids=["CWE-79"]
        )
        
        self.assertEqual(cve.cve_id, "CVE-2023-12345")
        self.assertEqual(cve.cvss_score, 7.5)
        self.assertEqual(cve.severity, "HIGH")
    
    def test_cve_to_dict(self):
        """Test converting CVEDetails to dictionary"""
        cve = CVEDetails(
            cve_id="CVE-2023-12345",
            description="Test",
            cvss_score=5.0,
            severity="MEDIUM",
            published_date="2023-01-01",
            last_modified="2023-01-02",
            affected_products=[],
            references=[],
            cwe_ids=[]
        )
        
        cve_dict = cve.to_dict()
        
        self.assertIsInstance(cve_dict, dict)
        self.assertEqual(cve_dict['cve_id'], "CVE-2023-12345")
        self.assertEqual(cve_dict['cvss_score'], 5.0)


class TestCVEProvider(unittest.TestCase):
    """Test CVEProvider class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create temporary cache directory
        self.temp_dir = tempfile.mkdtemp()
        self.provider = CVEProvider(cache_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures"""
        # Remove temporary directory
        shutil.rmtree(self.temp_dir)
    
    def test_provider_initialization(self):
        """Test CVE provider initialization"""
        self.assertIsNotNone(self.provider)
        self.assertTrue(Path(self.temp_dir).exists())
        self.assertEqual(self.provider.cache_duration, timedelta(days=7))
    
    def test_cache_path_generation(self):
        """Test cache file path generation"""
        cache_path = self.provider._get_cache_path("CVE-2023-12345")
        
        expected = Path(self.temp_dir) / "CVE-2023-12345.json"
        self.assertEqual(cache_path, expected)
    
    def test_save_and_load_cache(self):
        """Test saving and loading CVE data from cache"""
        # Create test CVE
        cve = CVEDetails(
            cve_id="CVE-2023-TEST",
            description="Test CVE",
            cvss_score=8.0,
            severity="HIGH",
            published_date="2023-01-01",
            last_modified="2023-01-02",
            affected_products=["test:1.0"],
            references=["https://test.com"],
            cwe_ids=["CWE-123"]
        )
        
        # Save to cache
        self.provider._save_to_cache(cve)
        
        # Load from cache
        loaded = self.provider._load_from_cache("CVE-2023-TEST")
        
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.cve_id, "CVE-2023-TEST")
        self.assertEqual(loaded.cvss_score, 8.0)
        self.assertEqual(loaded.severity, "HIGH")
    
    def test_cache_expiration(self):
        """Test that old cache expires"""
        # Create test CVE
        cve = CVEDetails(
            cve_id="CVE-2023-OLD",
            description="Old CVE",
            cvss_score=5.0,
            severity="MEDIUM",
            published_date="2023-01-01",
            last_modified="2023-01-02",
            affected_products=[],
            references=[],
            cwe_ids=[]
        )
        
        # Save to cache
        self.provider._save_to_cache(cve)
        
        # Modify cache file timestamp to be old
        cache_path = self.provider._get_cache_path("CVE-2023-OLD")
        old_time = (datetime.now() - timedelta(days=10)).timestamp()
        os.utime(cache_path, (old_time, old_time))
        
        # Cache should be invalid
        self.assertFalse(self.provider._is_cache_valid(cache_path))
        
        # Loading should return None
        loaded = self.provider._load_from_cache("CVE-2023-OLD")
        self.assertIsNone(loaded)
    
    def test_invalid_cve_id_format(self):
        """Test handling of invalid CVE ID format"""
        result = self.provider.get_cve_details("INVALID-123")
        
        self.assertIsNone(result)
    
    @patch('cve_provider.requests.Session.get')
    def test_get_cve_details_from_api(self, mock_get):
        """Test fetching CVE details from API"""
        # Mock API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'totalResults': 1,
            'vulnerabilities': [{
                'cve': {
                    'id': 'CVE-2023-12345',
                    'descriptions': [
                        {'lang': 'en', 'value': 'Test vulnerability description'}
                    ],
                    'metrics': {
                        'cvssMetricV31': [{
                            'cvssData': {
                                'baseScore': 7.5,
                                'baseSeverity': 'HIGH'
                            }
                        }]
                    },
                    'published': '2023-01-01T00:00:00',
                    'lastModified': '2023-01-02T00:00:00',
                    'references': [
                        {'url': 'https://example.com/ref1'},
                        {'url': 'https://example.com/ref2'}
                    ],
                    'weaknesses': [{
                        'description': [
                            {'lang': 'en', 'value': 'CWE-79'}
                        ]
                    }],
                    'configurations': []
                }
            }]
        }
        mock_get.return_value = mock_response
        
        # Fetch CVE
        cve = self.provider.get_cve_details("CVE-2023-12345", use_cache=False)
        
        # Verify result
        self.assertIsNotNone(cve)
        self.assertEqual(cve.cve_id, "CVE-2023-12345")
        self.assertEqual(cve.cvss_score, 7.5)
        self.assertEqual(cve.severity, "HIGH")
        self.assertIn("Test vulnerability", cve.description)
    
    @patch('cve_provider.requests.Session.get')
    def test_get_cve_details_not_found(self, mock_get):
        """Test handling of CVE not found in API"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'totalResults': 0,
            'vulnerabilities': []
        }
        mock_get.return_value = mock_response
        
        cve = self.provider.get_cve_details("CVE-9999-99999", use_cache=False)
        
        self.assertIsNone(cve)
    
    @patch('cve_provider.requests.Session.get')
    def test_api_error_handling(self, mock_get):
        """Test handling of API errors"""
        mock_get.side_effect = Exception("Network error")
        
        cve = self.provider.get_cve_details("CVE-2023-12345", use_cache=False)
        
        self.assertIsNone(cve)
    
    def test_get_service_cves(self):
        """Test getting CVEs for a service"""
        # Mock the get_cve_details method
        with patch.object(self.provider, 'get_cve_details') as mock_get:
            mock_cve = CVEDetails(
                cve_id="CVE-2019-0708",
                description="BlueKeep",
                cvss_score=9.8,
                severity="CRITICAL",
                published_date="2019-05-16",
                last_modified="2019-05-17",
                affected_products=["microsoft:windows"],
                references=["https://example.com"],
                cwe_ids=["CWE-20"]
            )
            mock_get.return_value = mock_cve
            
            # Get RDP CVEs
            cves = self.provider.get_service_cves("rdp")
            
            # Should return CVEs
            self.assertGreater(len(cves), 0)
            self.assertEqual(cves[0].cve_id, "CVE-2019-0708")
    
    def test_get_service_cves_unknown_service(self):
        """Test getting CVEs for unknown service"""
        cves = self.provider.get_service_cves("unknown_service_xyz")
        
        # Should return empty list
        self.assertEqual(len(cves), 0)
    
    def test_enrich_scan_results(self):
        """Test enriching scan results with CVE data"""
        # Mock scan results
        scan_results = [
            {
                'port': 3389,
                'service': 'rdp',
                'banner': 'Microsoft RDP'
            },
            {
                'port': 22,
                'service': 'ssh',
                'banner': 'OpenSSH'
            }
        ]
        
        # Mock get_service_cves
        with patch.object(self.provider, 'get_service_cves') as mock_get_cves:
            mock_cve = CVEDetails(
                cve_id="CVE-2019-0708",
                description="BlueKeep",
                cvss_score=9.8,
                severity="CRITICAL",
                published_date="2019-05-16",
                last_modified="2019-05-17",
                affected_products=[],
                references=[],
                cwe_ids=[]
            )
            mock_get_cves.return_value = [mock_cve]
            
            # Enrich results
            enriched = self.provider.enrich_scan_results(scan_results)
            
            # Verify enrichment
            self.assertEqual(len(enriched), 2)
            self.assertIn('cves', enriched[0])
            self.assertIn('cve_count', enriched[0])
            self.assertEqual(enriched[0]['cve_count'], 1)
            self.assertEqual(enriched[0]['highest_cve_severity'], 'CRITICAL')
    
    def test_clear_cache(self):
        """Test clearing cache"""
        # Create some cached CVEs
        for i in range(3):
            cve = CVEDetails(
                cve_id=f"CVE-2023-{i}",
                description=f"Test {i}",
                cvss_score=5.0,
                severity="MEDIUM",
                published_date="2023-01-01",
                last_modified="2023-01-02",
                affected_products=[],
                references=[],
                cwe_ids=[]
            )
            self.provider._save_to_cache(cve)
        
        # Verify cache files exist
        cache_files = list(Path(self.temp_dir).glob("CVE-*.json"))
        self.assertEqual(len(cache_files), 3)
        
        # Clear cache
        self.provider.clear_cache()
        
        # Verify cache is empty
        cache_files = list(Path(self.temp_dir).glob("CVE-*.json"))
        self.assertEqual(len(cache_files), 0)
    
    def test_rate_limiting(self):
        """Test API rate limiting"""
        import time
        
        start_time = time.time()
        
        # Make multiple requests (should be rate limited)
        self.provider._rate_limit()
        self.provider._rate_limit()
        
        elapsed = time.time() - start_time
        
        # Should take at least the minimum interval
        self.assertGreaterEqual(elapsed, self.provider.min_request_interval)


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.provider = CVEProvider(cache_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up"""
        shutil.rmtree(self.temp_dir)
    
    @unittest.skip("Requires real API access - use for manual testing")
    def test_real_api_fetch(self):
        """Test fetching real CVE data from NVD (manual test only)"""
        # This test requires internet connection and hits real NVD API
        # Skip in automated tests to avoid rate limiting
        
        cve = self.provider.get_cve_details("CVE-2019-0708", use_cache=False)
        
        self.assertIsNotNone(cve)
        self.assertEqual(cve.cve_id, "CVE-2019-0708")
        self.assertGreater(cve.cvss_score, 0)
        self.assertIn("CRITICAL", cve.severity.upper())


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestCVEDetails))
    suite.addTests(loader.loadTestsFromTestCase(TestCVEProvider))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if result.wasSuccessful():
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed")
    
    return result


if __name__ == "__main__":
    run_tests()

