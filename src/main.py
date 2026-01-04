#!/usr/bin/env python3
"""
Enhanced Security Audit Tool v2.0
A comprehensive port scanning and vulnerability detection tool
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
    "vnc": {
        "name": "VNC Service Detected",
        "description": "VNC may have weak authentication",
        "severity": "medium",
        "recommendation": "Use SSH tunneling"
    },
    "redis": {
        "name": "Redis Database Exposed",
        "description": "Redis exposed without authentication",
        "severity": "critical",
        "recommendation": "Enable authentication, bind to localhost"
    },
    "elasticsearch": {
        "name": "Elasticsearch Exposed",
        "description": "Search engine accessible without auth",
        "severity": "high",
        "recommendation": "Enable X-Pack security"
    }
}


# Common port to service mapping
PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb", 27018: "mongodb"
}


# ============================================================================
# Scanner Class
# ============================================================================

class SecurityScanner:
    """Main security scanning engine"""
    
    def __init__(self, target: str, timeout: float = 1.0, 
                 max_workers: int = 100, verbose: bool = False,
                 api_token: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose
        self.api_token = api_token
        self.results: List[ScanResult] = []
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Configure logging based on verbosity"""
        log_level = logging.DEBUG if self.verbose else logging.INFO
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def scan_port(self, port: int) -> Optional[ScanResult]:
        """Scan a single port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    # Port is open, get service info
                    service = PORT_SERVICES.get(port, "unknown")
                    banner = self._grab_banner(sock, port)
                    
                    # Check for vulnerabilities
                    vulnerabilities, severity = self._check_vulnerabilities(port, service, banner)
                    
                    scan_result = ScanResult(
                        port=port,
                        state="open",
                        service=service,
                        banner=banner,
                        vulnerabilities=vulnerabilities,
                        severity=severity
                    )
                    
                    if self.verbose:
                        self._log_result(scan_result)
                    
                    return scan_result
                    
        except socket.timeout:
            self.logger.debug(f"Port {port}: Timeout")
        except socket.error as e:
            self.logger.debug(f"Port {port}: Error - {e}")
        except Exception as e:
            self.logger.error(f"Port {port}: Unexpected error - {e}")
            
        return None
        
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            sock.settimeout(2.0)
            
            # Send protocol-specific probes
            if port == 80 or port == 8080:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 25:
                pass  # SMTP sends banner automatically
            else:
                sock.send(b"\r\n")
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]  # Limit banner length
            
        except:
            return ""
            
    def _check_vulnerabilities(self, port: int, service: str, banner: str) -> Tuple[List[str], str]:
        """Check for known vulnerabilities"""
        vulnerabilities = []
        severity = "info"
        
        # Check service-based vulnerabilities
        if service in VULNERABILITY_DB:
            vuln_info = VULNERABILITY_DB[service]
            vulnerabilities.append(
                f"{vuln_info['name']}: {vuln_info['description']} - {vuln_info['recommendation']}"
            )
            severity = vuln_info['severity']
            
        # Check banner for version vulnerabilities (basic)
        if banner:
            # Example: Check for old versions
            if "OpenSSH" in banner and any(v in banner for v in ["5.3", "5.8", "6.6"]):
                vulnerabilities.append("Potentially outdated OpenSSH version detected")
                severity = max(severity, "medium", key=lambda x: ["info", "low", "medium", "high", "critical"].index(x))
                
        return vulnerabilities, severity
        
    def _log_result(self, result: ScanResult):
        """Log scan result with color coding"""
        severity_colors = {
            "critical": "\033[91m",  # Red
            "high": "\033[93m",      # Yellow
            "medium": "\033[94m",    # Blue
            "low": "\033[92m",       # Green
            "info": "\033[0m"        # Default
        }
        reset = "\033[0m"
        
        color = severity_colors.get(result.severity, reset)
        
        print(f"{color}[+] Port {result.port} ({result.service}) - {result.state.upper()}{reset}")
        
        if result.banner:
            print(f"    Banner: {result.banner[:100]}")
            
        if result.vulnerabilities:
            print(f"    {color}[!] Vulnerabilities found:{reset}")
            for vuln in result.vulnerabilities:
                print(f"        - {vuln}")
                
    def scan_range(self, port_range: str) -> List[ScanResult]:
        """Scan a range of ports"""
        ports = self._parse_port_range(port_range)
        
        print(f"\n{'='*70}")
        print(f"Starting Security Scan")
        print(f"{'='*70}")
        print(f"Target: {self.target}")
        print(f"Ports: {len(ports)} ports to scan")
        print(f"Timeout: {self.timeout}s")
        print(f"Workers: {self.max_workers}")
        print(f"{'='*70}\n")
        
        start_time = datetime.now()
        
        # Scan with progress bar
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            # Use tqdm for progress tracking
            with tqdm(total=len(ports), desc="Scanning", unit="port") as pbar:
                for future in as_completed(future_to_port):
                    result = future.result()
                    if result:
                        self.results.append(result)
                    pbar.update(1)
                    
        duration = (datetime.now() - start_time).total_seconds()
        
        # Print summary
        self._print_summary(duration)
        
        return self.results
        
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string into list of ports"""
        ports = []
        
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
                
        return sorted(set(ports))  # Remove duplicates and sort
        
    def _print_summary(self, duration: float):
        """Print scan summary"""
        print(f"\n{'='*70}")
        print(f"Scan Complete!")
        print(f"{'='*70}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Ports Scanned: {len(self.results) if self.results else 0}")
        print(f"Open Ports: {len([r for r in self.results if r.state == 'open'])}")
        
        # Count vulnerabilities by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for result in self.results:
            if result.vulnerabilities:
                severity_counts[result.severity] = severity_counts.get(result.severity, 0) + 1
                
        if any(severity_counts.values()):
            print(f"\nVulnerabilities Found:")
            for severity, count in severity_counts.items():
                if count > 0:
                    print(f"  {severity.upper()}: {count}")
                    
        print(f"{'='*70}\n")
        
    def get_geo_info(self) -> Optional[Dict]:
        """Get geolocation information for target IP"""
        if not self.api_token:
            return None
            
        try:
            response = requests.get(
                f"https://ipinfo.io/{self.target}?token={self.api_token}",
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json()
                
        except Exception as e:
            self.logger.error(f"Failed to get geo info: {e}")
            
        return None
        
    def generate_report(self, output_file: str):
        """Generate JSON report"""
        scan_report = ScanReport(
            target=self.target,
            scan_time=datetime.now().isoformat(),
            duration=0.0,  # Will be updated
            total_ports_scanned=len(self.results),
            open_ports=len([r for r in self.results if r.state == "open"]),
            results=self.results,
            geo_info=self.get_geo_info()
        )
        
        # Save to file
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(scan_report.to_dict(), f, indent=2)
            
        print(f"[+] Report saved to: {output_path}")


# ============================================================================
# Main Function
# ============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Enhanced Security Audit Tool v2.0 - Port Scanner with Vulnerability Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 127.0.0.1 -p 1-1000                    # Scan ports 1-1000
  %(prog)s 127.0.0.1 -p 22,80,443 -v              # Scan specific ports (verbose)
  %(prog)s 127.0.0.1 -p 1-65535 -w 500            # Full scan with 500 workers
  %(prog)s 127.0.0.1 -p 1-1000 -o report.json     # Save results to JSON
  %(prog)s 8.8.8.8 -p 1-100 --api-token TOKEN     # Scan with geolocation

⚠️  Legal Notice:
Only scan systems you own or have explicit permission to test.
Unauthorized scanning may be illegal in your jurisdiction.
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1000', 
                       help='Port range to scan (default: 1-1000). Examples: 1-1000, 22,80,443, 1-100,8000-9000')
    parser.add_argument('-t', '--timeout', type=float, default=1.0,
                       help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('-w', '--workers', type=int, default=100,
                       help='Number of concurrent workers (default: 100)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    parser.add_argument('--api-token', help='IPinfo.io API token for geolocation')
    
    args = parser.parse_args()
    
    # Validate target
    try:
        socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"ERROR: Cannot resolve hostname: {args.target}")
        sys.exit(1)
        
    # Create scanner and run
    try:
        scanner = SecurityScanner(
            target=args.target,
            timeout=args.timeout,
            max_workers=args.workers,
            verbose=args.verbose,
            api_token=args.api_token
        )
        
        # Run scan
        scanner.scan_range(args.ports)
        
        # Generate report if requested
        if args.output:
            scanner.generate_report(args.output)
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
