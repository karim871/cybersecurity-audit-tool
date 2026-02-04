#!/usr/bin/env python3
"""
Enhanced Security Audit Tool v2.0 with CVE Intelligence
A comprehensive port scanning and vulnerability detection tool with NVD integration
Author: Abdelkrim Zouaki
"""

import socket
import argparse
import json
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path

try:
    import requests
    from tqdm import tqdm
except ImportError:
    print("ERROR: Required packages not installed!")
    print("Please run: pip install requests tqdm")
    sys.exit(1)

# Import CVE Provider
try:
    from cve_provider import CVEProvider
    CVE_AVAILABLE = True
except ImportError:
    CVE_AVAILABLE = False
    print("WARNING: CVE Provider not available. CVE enrichment will be disabled.")

# ============================================================================
# Configuration and Data Classes
# ============================================================================

@dataclass
class ScanResult:
    """Represents a scan result for a single port"""
    port: int
    state: str
    service: str = "unknown"
    banner: str = ""
    vulnerabilities: List[str] = field(default_factory=list)
    severity: str = "info"
    
    # CVE enrichment fields (new)
    cves: List[Dict] = field(default_factory=list)
    cve_count: int = 0
    highest_cve_severity: str = "NONE"
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    """Complete scan report with metadata"""
    target: str
    scan_time: str
    duration: float
    total_ports_scanned: int
    open_ports: int
    results: List[ScanResult]
    geo_info: Optional[Dict] = None
    
    # CVE summary (new)
    total_cves: int = 0
    critical_cves: int = 0
    high_cves: int = 0
    
    def to_dict(self) -> dict:
        data = asdict(self)
        data['results'] = [r.to_dict() for r in self.results]
        return data


# Known vulnerable services with severity levels
VULNERABILITY_DB = {
    "ftp": {
        "name": "FTP Service Detected",
        "description": "FTP transmits credentials in plaintext",
        "severity": "high",
        "recommendation": "Use SFTP or FTPS instead"
    },
    "telnet": {
        "name": "Telnet Service Detected", 
        "description": "Telnet is unencrypted and insecure",
        "severity": "critical",
        "recommendation": "Replace with SSH"
    },
    "smtp": {
        "name": "SMTP Service Detected",
        "description": "May be vulnerable to relay attacks",
        "severity": "medium",
        "recommendation": "Ensure proper authentication and TLS"
    },
    "mysql": {
        "name": "MySQL Database Exposed",
        "description": "Database should not be internet-facing",
        "severity": "high",
        "recommendation": "Restrict access to trusted IPs only"
    },
    "mongodb": {
        "name": "MongoDB Database Exposed",
        "description": "Database should not be internet-facing",
        "severity": "high", 
        "recommendation": "Enable authentication and restrict access"
    },
    "rdp": {
        "name": "RDP Service Detected",
        "description": "Remote Desktop exposed to internet",
        "severity": "high",
        "recommendation": "Use VPN or restrict IPs"
    },
    "ssh": {
        "name": "SSH Service Detected",
        "description": "Secure Shell access available",
        "severity": "info",
        "recommendation": "Ensure strong authentication and keep updated"
    },
    "http": {
        "name": "HTTP Service Detected",
        "description": "Unencrypted web traffic",
        "severity": "medium",
        "recommendation": "Use HTTPS instead"
    },
    "postgresql": {
        "name": "PostgreSQL Database Exposed",
        "description": "Database should not be internet-facing",
        "severity": "high",
        "recommendation": "Restrict access to trusted networks"
    },
    "redis": {
        "name": "Redis Service Exposed",
        "description": "In-memory database exposed",
        "severity": "high",
        "recommendation": "Enable authentication and bind to localhost"
    },
    "vnc": {
        "name": "VNC Service Detected",
        "description": "Remote desktop protocol exposed",
        "severity": "high",
        "recommendation": "Use strong passwords and VPN access"
    }
}

# Common service port mappings
SERVICE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    27017: "mongodb"
}

# ============================================================================
# Logging Configuration
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_scan.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# ============================================================================
# Security Scanner Class
# ============================================================================

class SecurityScanner:
    """
    Enhanced Security Scanner with CVE Intelligence
    
    Features:
    - Multi-threaded port scanning
    - Service detection and banner grabbing
    - Vulnerability detection
    - CVE enrichment from NVD database
    - Geolocation lookup
    - Comprehensive reporting
    """
    
    def __init__(self, target: str, port_range: str, max_workers: int = 100,
                 timeout: float = 1.0, verbose: bool = False, 
                 enable_cve: bool = True, api_token: Optional[str] = None):
        """
        Initialize Security Scanner
        
        Args:
            target: Target IP address or hostname
            port_range: Port range (e.g., "1-1000" or "80,443,3306")
            max_workers: Maximum concurrent workers
            timeout: Socket timeout in seconds
            verbose: Enable verbose output
            enable_cve: Enable CVE enrichment
            api_token: Optional API token for geolocation
        """
        self.target = target
        self.max_workers = max_workers
        self.timeout = timeout
        self.verbose = verbose
        self.api_token = api_token
        
        # Parse port range
        self.ports = self._parse_port_range(port_range)
        
        # CVE Provider integration
        self.enable_cve = enable_cve and CVE_AVAILABLE
        if self.enable_cve:
            try:
                self.cve_provider = CVEProvider(cache_dir="./data/cve_cache")
                logger.info("CVE enrichment enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize CVE provider: {e}")
                self.enable_cve = False
        
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        logger.info(f"Scanner initialized for {target}")
        logger.info(f"Ports to scan: {len(self.ports)}")
        logger.info(f"Max workers: {max_workers}")
        logger.info(f"CVE enrichment: {'enabled' if self.enable_cve else 'disabled'}")
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string into list of ports"""
        ports = []
        
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))
    
    def _scan_port(self, port: int) -> Optional[ScanResult]:
        """
        Scan a single port
        
        Args:
            port: Port number to scan
            
        Returns:
            ScanResult object or None if port is closed
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # Port is open - get service and banner
                service = SERVICE_PORTS.get(port, "unknown")
                banner = self._grab_banner(sock)
                
                # Check for vulnerabilities
                vulnerabilities = []
                severity = "info"
                
                if service in VULNERABILITY_DB:
                    vuln_info = VULNERABILITY_DB[service]
                    vulnerabilities.append(vuln_info['name'])
                    severity = vuln_info['severity']
                
                scan_result = ScanResult(
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                    vulnerabilities=vulnerabilities,
                    severity=severity
                )
                
                sock.close()
                
                logger.debug(f"Port {port} is open - {service}")
                return scan_result
            
            sock.close()
            return None
            
        except socket.timeout:
            logger.debug(f"Port {port} timeout")
            return None
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")
            return None
    
    def _grab_banner(self, sock: socket.socket) -> str:
        """
        Attempt to grab service banner
        
        Args:
            sock: Connected socket
            
        Returns:
            Banner string or empty string
        """
        try:
            sock.settimeout(2.0)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]  # Limit banner length
        except:
            return ""
    
    def _get_geolocation(self) -> Optional[Dict]:
        """
        Get geolocation information for target IP
        
        Returns:
            Geolocation data or None
        """
        try:
            if self.api_token:
                url = f"https://ipinfo.io/{self.target}?token={self.api_token}"
            else:
                url = f"https://ipinfo.io/{self.target}/json"
            
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Geolocation lookup failed: {response.status_code}")
                return None
        except Exception as e:
            logger.warning(f"Geolocation error: {e}")
            return None
    
    def enrich_with_cves(self, scan_results: List[ScanResult]) -> List[ScanResult]:
        """
        Enrich scan results with CVE information from NVD database
        
        Args:
            scan_results: List of ScanResult objects
            
        Returns:
            Enriched scan results with CVE data
        """
        if not self.enable_cve:
            logger.debug("CVE enrichment disabled")
            return scan_results
        
        logger.info("Enriching scan results with CVE data...")
        
        # Convert to dicts for CVE provider
        results_as_dicts = []
        for result in scan_results:
            if result.state == "open":
                results_as_dicts.append({
                    'port': result.port,
                    'service': result.service,
                    'banner': result.banner,
                    'status': result.state
                })
        
        try:
            # Enrich with CVE data
            enriched_dicts = self.cve_provider.enrich_scan_results(results_as_dicts)
            
            # Update original ScanResult objects
            dict_index = 0
            for result in scan_results:
                if result.state == "open" and dict_index < len(enriched_dicts):
                    enriched = enriched_dicts[dict_index]
                    result.cves = enriched.get('cves', [])
                    result.cve_count = enriched.get('cve_count', 0)
                    result.highest_cve_severity = enriched.get('highest_cve_severity', 'NONE')
                    
                    # Log CVE findings
                    if result.cve_count > 0:
                        logger.info(f"Port {result.port} ({result.service}): {result.cve_count} CVEs found - Highest: {result.highest_cve_severity}")
                    
                    dict_index += 1
            
            logger.info(f"CVE enrichment complete")
            
        except Exception as e:
            logger.error(f"CVE enrichment failed: {e}")
        
        return scan_results
    
    def scan(self) -> ScanReport:
        """
        Perform complete security scan
        
        Returns:
            ScanReport object with results
        """
        logger.info(f"Starting scan of {self.target}")
        start_time = datetime.now()
        
        # Perform port scan with progress bar
        results = []
        
        if self.verbose:
            print(f"\n🔍 Scanning {self.target} ({len(self.ports)} ports)")
            print(f"⚡ Using {self.max_workers} concurrent workers\n")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all port scan tasks
            future_to_port = {executor.submit(self._scan_port, port): port 
                             for port in self.ports}
            
            # Process results with progress bar
            if self.verbose:
                iterator = tqdm(as_completed(future_to_port), 
                              total=len(self.ports),
                              desc="Scanning",
                              unit="port")
            else:
                iterator = as_completed(future_to_port)
            
            for future in iterator:
                result = future.result()
                if result:
                    results.append(result)
        
        # Sort results by port number
        results.sort(key=lambda x: x.port)
        
        # Enrich with CVE data
        if self.enable_cve and results:
            if self.verbose:
                print("\n🔬 Enriching results with CVE intelligence...")
            results = self.enrich_with_cves(results)
        
        # Get geolocation
        geo_info = None
        if self.api_token:
            if self.verbose:
                print("🌍 Looking up geolocation...")
            geo_info = self._get_geolocation()
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Calculate CVE statistics
        total_cves = sum(r.cve_count for r in results)
        critical_cves = sum(1 for r in results if r.highest_cve_severity == "CRITICAL")
        high_cves = sum(1 for r in results if r.highest_cve_severity == "HIGH")
        
        # Create report
        report = ScanReport(
            target=self.target,
            scan_time=start_time.isoformat(),
            duration=duration,
            total_ports_scanned=len(self.ports),
            open_ports=len(results),
            results=results,
            geo_info=geo_info,
            total_cves=total_cves,
            critical_cves=critical_cves,
            high_cves=high_cves
        )
        
        logger.info(f"Scan complete: {len(results)} open ports found in {duration:.2f}s")
        if self.enable_cve:
            logger.info(f"CVE Summary: {total_cves} total, {critical_cves} critical, {high_cves} high")
        
        return report
    
    def display_results(self, report: ScanReport):
        """
        Display scan results in a formatted way
        
        Args:
            report: ScanReport object
        """
        print("\n" + "="*80)
        print(f"🔒 Security Scan Report - {report.target}")
        print("="*80)
        print(f"Scan Time: {report.scan_time}")
        print(f"Duration: {report.duration:.2f} seconds")
        print(f"Ports Scanned: {report.total_ports_scanned}")
        print(f"Open Ports: {report.open_ports}")
        
        if self.enable_cve and report.total_cves > 0:
            print(f"\n📊 CVE Summary:")
            print(f"   Total CVEs: {report.total_cves}")
            print(f"   Critical: {report.critical_cves}")
            print(f"   High: {report.high_cves}")
        
        if report.geo_info:
            print(f"\n🌍 Geolocation:")
            print(f"   Location: {report.geo_info.get('city', 'N/A')}, {report.geo_info.get('country', 'N/A')}")
            print(f"   ISP: {report.geo_info.get('org', 'N/A')}")
        
        if report.results:
            print(f"\n📋 Open Ports:")
            print("-"*80)
            
            for result in report.results:
                # Color coding based on severity
                severity_colors = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "info": "🟢"
                }
                icon = severity_colors.get(result.severity, "⚪")
                
                # Basic port info
                print(f"\n{icon} Port {result.port} - {result.service.upper()} [{result.severity.upper()}]")
                
                if result.banner:
                    print(f"   Banner: {result.banner[:100]}")
                
                if result.vulnerabilities:
                    print(f"   Vulnerabilities:")
                    for vuln in result.vulnerabilities:
                        print(f"      - {vuln}")
                
                # CVE information (new)
                if result.cve_count > 0:
                    print(f"   🔬 CVE Intelligence: {result.cve_count} known vulnerabilities")
                    print(f"   Highest Severity: {result.highest_cve_severity}")
                    
                    # Show first 2 CVEs with details
                    for i, cve in enumerate(result.cves[:2]):
                        print(f"\n   [{cve['cve_id']}] - {cve['severity']}")
                        print(f"      CVSS: {cve['cvss_score']}")
                        print(f"      {cve['description'][:150]}...")
                    
                    if result.cve_count > 2:
                        print(f"   ... and {result.cve_count - 2} more CVEs (see JSON report)")
        
        print("\n" + "="*80)
    
    def save_report(self, report: ScanReport, output_file: str):
        """
        Save scan report to JSON file
        
        Args:
            report: ScanReport object
            output_file: Output file path
        """
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            
            logger.info(f"Report saved to {output_file}")
            print(f"\n💾 Report saved to: {output_file}")
            
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            print(f"❌ Error saving report: {e}")


# ============================================================================
# Main Function
# ============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Enhanced Security Audit Tool v2.0 with CVE Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1 -p 1-1000
  %(prog)s scanme.nmap.org -p 22,80,443 -v
  %(prog)s 10.0.0.1 -p 1-65535 -w 500 -o report.json
  %(prog)s 192.168.1.1 -p 1-1000 --enable-cve -v
  %(prog)s example.com -p 80,443 --no-cve

CVE Enrichment:
  By default, CVE enrichment is enabled. The tool will query the NVD database
  to enrich scan results with vulnerability intelligence (CVSS scores, severity,
  affected products, etc.). Use --no-cve to disable.
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', required=True,
                       help='Port range (e.g., 1-1000 or 22,80,443)')
    parser.add_argument('-w', '--workers', type=int, default=100,
                       help='Maximum concurrent workers (default: 100)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0,
                       help='Socket timeout in seconds (default: 1.0)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-o', '--output', 
                       help='Output file for JSON report')
    parser.add_argument('--api-token',
                       help='API token for geolocation lookup')
    
    # CVE options
    cve_group = parser.add_mutually_exclusive_group()
    cve_group.add_argument('--enable-cve', action='store_true', default=True,
                          help='Enable CVE enrichment (default)')
    cve_group.add_argument('--no-cve', dest='enable_cve', action='store_false',
                          help='Disable CVE enrichment')
    
    args = parser.parse_args()
    
    # Display banner
    if args.verbose:
        print("""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     Enhanced Security Audit Tool v2.0 with CVE Intelligence      ║
║                                                                   ║
║     Multi-threaded port scanner with vulnerability detection     ║
║     and real-time threat intelligence from NVD database          ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
        """)
    
    try:
        # Create scanner
        scanner = SecurityScanner(
            target=args.target,
            port_range=args.ports,
            max_workers=args.workers,
            timeout=args.timeout,
            verbose=args.verbose,
            enable_cve=args.enable_cve,
            api_token=args.api_token
        )
        
        # Perform scan
        report = scanner.scan()
        
        # Display results
        scanner.display_results(report)
        
        # Save report if requested
        if args.output:
            scanner.save_report(report, args.output)
        
        # Exit with appropriate code
        if report.open_ports > 0:
            if report.critical_cves > 0:
                sys.exit(2)  # Critical vulnerabilities found
            elif report.high_cves > 0:
                sys.exit(1)  # High vulnerabilities found
        
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
