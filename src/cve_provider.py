#!/usr/bin/env python3
"""
CVE Provider Module
Integrates with National Vulnerability Database (NVD) for vulnerability enrichment
"""

import json
import logging
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict
import time

logger = logging.getLogger(__name__)

@dataclass
class CVEDetails:
    """Represents detailed CVE information"""
    cve_id: str
    description: str
    cvss_score: float
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    published_date: str
    last_modified: str
    affected_products: List[str]
    references: List[str]
    cwe_ids: List[str]  # Common Weakness Enumeration IDs
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class CVEProvider:
    """
    Provides CVE vulnerability information from NVD database
    
    Features:
    - Caches CVE data locally to reduce API calls
    - Rate limiting to respect NVD API limits (5 requests per 30 seconds)
    - Offline mode with fallback to cached data
    - Service-to-CVE mapping for common vulnerable services
    """
    
    # NVD API v2.0 endpoint
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Common service to CVE mappings (examples - expand as needed)
    SERVICE_CVE_MAP = {
        "ftp": ["CVE-2023-38408", "CVE-2020-15778"],  # vsftpd vulnerabilities
        "telnet": ["CVE-2020-10188"],  # Telnet vulnerabilities
        "ssh": ["CVE-2023-48795", "CVE-2023-51385"],  # OpenSSH vulnerabilities
        "http": ["CVE-2023-44487", "CVE-2023-25690"],  # Apache/nginx
        "mysql": ["CVE-2023-22084", "CVE-2022-21595"],  # MySQL
        "postgresql": ["CVE-2023-5869", "CVE-2023-5868"],  # PostgreSQL
        "mongodb": ["CVE-2023-1409"],  # MongoDB
        "redis": ["CVE-2022-35977", "CVE-2023-28856"],  # Redis
        "rdp": ["CVE-2019-0708"],  # BlueKeep
        "vnc": ["CVE-2023-40547"],  # VNC
    }
    
    def __init__(self, cache_dir: str = "./data/cve_cache", 
                 api_key: Optional[str] = None,
                 cache_duration_days: int = 7):
        """
        Initialize CVE Provider
        
        Args:
            cache_dir: Directory to store cached CVE data
            api_key: NVD API key (optional, but recommended for higher rate limits)
            cache_duration_days: How long to cache CVE data before refreshing
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key
        self.cache_duration = timedelta(days=cache_duration_days)
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 6  # 5 requests per 30 seconds = 6 sec between
        
        # Session for connection pooling
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})
        
        logger.info(f"CVE Provider initialized with cache dir: {self.cache_dir}")
    
    def _rate_limit(self):
        """Enforce rate limiting for NVD API"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _get_cache_path(self, cve_id: str) -> Path:
        """Get cache file path for a CVE ID"""
        return self.cache_dir / f"{cve_id}.json"
    
    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cached data is still valid"""
        if not cache_path.exists():
            return False
        
        file_time = datetime.fromtimestamp(cache_path.stat().st_mtime)
        age = datetime.now() - file_time
        
        return age < self.cache_duration
    
    def _load_from_cache(self, cve_id: str) -> Optional[CVEDetails]:
        """Load CVE details from cache"""
        cache_path = self._get_cache_path(cve_id)
        
        if not self._is_cache_valid(cache_path):
            return None
        
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
                return CVEDetails(**data)
        except Exception as e:
            logger.warning(f"Failed to load cache for {cve_id}: {e}")
            return None
    
    def _save_to_cache(self, cve_details: CVEDetails):
        """Save CVE details to cache"""
        cache_path = self._get_cache_path(cve_details.cve_id)
        
        try:
            with open(cache_path, 'w') as f:
                json.dump(cve_details.to_dict(), f, indent=2)
            logger.debug(f"Cached CVE data: {cve_details.cve_id}")
        except Exception as e:
            logger.warning(f"Failed to cache {cve_details.cve_id}: {e}")
    
    def get_cve_details(self, cve_id: str, use_cache: bool = True) -> Optional[CVEDetails]:
        """
        Fetch CVE details from NVD API or cache
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-12345")
            use_cache: Whether to use cached data if available
            
        Returns:
            CVEDetails object or None if not found
        """
        # Validate CVE ID format
        if not cve_id.startswith("CVE-"):
            logger.error(f"Invalid CVE ID format: {cve_id}")
            return None
        
        # Try cache first
        if use_cache:
            cached = self._load_from_cache(cve_id)
            if cached:
                logger.debug(f"Using cached data for {cve_id}")
                return cached
        
        # Fetch from API
        logger.info(f"Fetching {cve_id} from NVD API")
        self._rate_limit()
        
        try:
            url = f"{self.NVD_API_BASE}?cveId={cve_id}"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('totalResults', 0) == 0:
                logger.warning(f"CVE not found: {cve_id}")
                return None
            
            # Parse response
            vuln = data['vulnerabilities'][0]['cve']
            
            # Extract CVSS score and severity
            cvss_data = vuln.get('metrics', {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in cvss_data and cvss_data[version]:
                    metric = cvss_data[version][0]
                    cvss_score = metric.get('cvssData', {}).get('baseScore', 0.0)
                    severity = metric.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
                    break
            
            # Extract description
            descriptions = vuln.get('descriptions', [])
            description = next(
                (d['value'] for d in descriptions if d.get('lang') == 'en'),
                "No description available"
            )
            
            # Extract references
            references = [
                ref.get('url', '') for ref in vuln.get('references', [])
            ][:5]  # Limit to first 5 references
            
            # Extract CWE IDs
            weaknesses = vuln.get('weaknesses', [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_ids.append(desc.get('value', ''))
            
            # Extract affected products (simplified - could be more detailed)
            affected_products = []
            configurations = vuln.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        criteria = cpe_match.get('criteria', '')
                        if criteria:
                            # Extract product name from CPE string
                            parts = criteria.split(':')
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                version = parts[5] if len(parts) > 5 else '*'
                                affected_products.append(f"{vendor}:{product}:{version}")
            
            affected_products = list(set(affected_products))[:10]  # Limit to 10 unique
            
            cve_details = CVEDetails(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                published_date=vuln.get('published', ''),
                last_modified=vuln.get('lastModified', ''),
                affected_products=affected_products,
                references=references,
                cwe_ids=cwe_ids
            )
            
            # Cache the result
            self._save_to_cache(cve_details)
            
            return cve_details
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch {cve_id} from NVD: {e}")
            return None
        except Exception as e:
            logger.error(f"Error parsing CVE data for {cve_id}: {e}")
            return None
    
    def get_service_cves(self, service: str) -> List[CVEDetails]:
        """
        Get known CVEs for a service type
        
        Args:
            service: Service name (e.g., "ftp", "ssh", "mysql")
            
        Returns:
            List of CVEDetails objects
        """
        service_lower = service.lower()
        cve_ids = self.SERVICE_CVE_MAP.get(service_lower, [])
        
        results = []
        for cve_id in cve_ids:
            details = self.get_cve_details(cve_id)
            if details:
                results.append(details)
        
        return results
    
    def enrich_scan_results(self, scan_results: List[Dict]) -> List[Dict]:
        """
        Enrich scan results with CVE information
        
        Args:
            scan_results: List of scan result dictionaries with 'service' field
            
        Returns:
            Enriched scan results with 'cves' field added
        """
        enriched = []
        
        for result in scan_results:
            service = result.get('service', '').lower()
            
            # Get CVEs for this service
            cves = self.get_service_cves(service)
            
            # Add CVE information to result
            enriched_result = result.copy()
            enriched_result['cves'] = [cve.to_dict() for cve in cves]
            enriched_result['cve_count'] = len(cves)
            
            if cves:
                # Add highest severity
                severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
                highest_severity = 'UNKNOWN'
                for sev in severities:
                    if any(cve.severity == sev for cve in cves):
                        highest_severity = sev
                        break
                enriched_result['highest_cve_severity'] = highest_severity
            
            enriched.append(enriched_result)
        
        return enriched
    
    def clear_cache(self):
        """Clear all cached CVE data"""
        for cache_file in self.cache_dir.glob("CVE-*.json"):
            cache_file.unlink()
        logger.info("CVE cache cleared")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize provider
    provider = CVEProvider()
    
    # Test fetching a specific CVE
    cve = provider.get_cve_details("CVE-2019-0708")  # BlueKeep (RDP vulnerability)
    if cve:
        print(f"\n{cve.cve_id}")
        print(f"Severity: {cve.severity} (CVSS: {cve.cvss_score})")
        print(f"Description: {cve.description[:200]}...")
        print(f"Affected: {', '.join(cve.affected_products[:3])}...")
    
    # Test service CVE lookup
    print("\n\nKnown RDP vulnerabilities:")
    rdp_cves = provider.get_service_cves("rdp")
    for cve in rdp_cves:
        print(f"- {cve.cve_id}: {cve.severity} ({cve.cvss_score})")
