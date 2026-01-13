#!/usr/bin/env python3
"""
Outil d'Audit de Cybersécurité
ATTENTION: À utiliser uniquement sur vos propres systèmes ou avec autorisation explicite
"""

import socket
import concurrent.futures
import requests
import json
import argparse
from datetime import datetime
from typing import List, Dict, Tuple
import sys

class PortScanner:
    """Scanner de ports avec gestion d'erreurs et threading optimisé"""
    
    def __init__(self, timeout=1, max_workers=100):
        self.timeout = timeout
        self.max_workers = max_workers
    
    def scan_port(self, ip: str, port: int) -> Tuple[int, bool, str]:
        """Scanne un port unique et retourne le statut"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    except:
                        banner = ""
                    return (port, True, banner)
        except Exception as e:
            pass
        return (port, False, "")
    
    def scan_ports(self, target: str, port_range: range) -> List[Dict]:
        """Scanne une plage de ports avec ThreadPoolExecutor"""
        print(f"[*] Scan de {target} sur les ports {port_range.start}-{port_range.stop-1}")
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_port, target, port): port 
                      for port in port_range}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, banner = future.result()
                if is_open:
                    service = self.identify_service(port, banner)
                    open_ports.append({
                        'port': port,
                        'banner': banner,
                        'service': service
                    })
                    print(f"[+] Port {port} ouvert - {service}")
        
        return open_ports
    
    def identify_service(self, port: int, banner: str) -> str:
        """Identifie le service basé sur le port et la bannière"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 8080: 'HTTP-Proxy', 27017: 'MongoDB'
        }
        
        service = common_ports.get(port, 'Unknown')
        if banner:
            service += f" ({banner[:50]})"
        return service


class VulnerabilityDetector:
    """Détecteur de vulnérabilités basiques"""
    
    def detect(self, open_ports: List[Dict]) -> List[Dict]:
        """Détecte les vulnérabilités potentielles"""
        vulnerabilities = []
        
        for port_info in open_ports:
            port = port_info['port']
            banner = port_info['banner'].lower()
            
            # Ports dangereux
            if port in [23, 445, 3389]:
                vulnerabilities.append({
                    'port': port,
                    'severity': 'HIGH',
                    'description': f'Port {port} exposé - service potentiellement dangereux'
                })
            
            # Versions obsolètes
            if 'ssh' in banner and any(v in banner for v in ['openssh_4', 'openssh_5']):
                vulnerabilities.append({
                    'port': port,
                    'severity': 'MEDIUM',
                    'description': 'Version SSH potentiellement obsolète détectée'
                })
            
            if 'apache' in banner and any(v in banner for v in ['2.2', '2.0']):
                vulnerabilities.append({
                    'port': port,
                    'severity': 'MEDIUM',
                    'description': 'Version Apache obsolète détectée'
                })
        
        return vulnerabilities


class GeolocationLookup:
    """Recherche de géolocalisation via API"""
    
    def get_location(self, ip: str) -> Dict:
        """Récupère les informations de géolocalisation"""
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"[!] Erreur de géolocalisation: {e}")
        return {}


class ReportGenerator:
    """Générateur de rapports d'audit"""
    
    def generate(self, target: str, open_ports: List[Dict], 
                 vulnerabilities: List[Dict], geo_info: Dict) -> str:
        """Génère un rapport détaillé"""
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'summary': {
                'total_open_ports': len(open_ports),
                'vulnerabilities_found': len(vulnerabilities)
            },
            'geolocation': geo_info,
            'open_ports': open_ports,
            'vulnerabilities': vulnerabilities
        }
        
        return json.dumps(report, indent=2)
    
    def save_report(self, report: str, filename: str):
        """Sauvegarde le rapport dans un fichier"""
        try:
            with open(filename, 'w') as f:
                f.write(report)
            print(f"[+] Rapport sauvegardé: {filename}")
        except Exception as e:
            print(f"[!] Erreur de sauvegarde: {e}")


def validate_ip(ip: str) -> bool:
    """Valide une adresse IP"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Outil d\'audit de cybersécurité - Usage éthique uniquement'
    )
    parser.add_argument('target', help='Adresse IP cible')
    parser.add_argument('-p', '--ports', default='1-1024', 
                       help='Plage de ports (ex: 1-1024)')
    parser.add_argument('-o', '--output', help='Fichier de sortie pour le rapport')
    parser.add_argument('-t', '--timeout', type=float, default=1.0,
                       help='Timeout pour chaque port (secondes)')
    parser.add_argument('-w', '--workers', type=int, default=100,
                       help='Nombre de threads parallèles')
    
    args = parser.parse_args()
    
    # Validation de l'IP
    if not validate_ip(args.target):
        print(f"[!] Adresse IP invalide: {args.target}")
        sys.exit(1)
    
    # Parsing de la plage de ports
    try:
        start, end = map(int, args.ports.split('-'))
        port_range = range(start, end + 1)
    except:
        print("[!] Format de ports invalide. Utilisez: 1-1024")
        sys.exit(1)
    
    print("="*60)
    print("OUTIL D'AUDIT DE CYBERSÉCURITÉ")
    print("ATTENTION: Usage éthique uniquement")
    print("="*60)
    
    # Scan de ports
    scanner = PortScanner(timeout=args.timeout, max_workers=args.workers)
    open_ports = scanner.scan_ports(args.target, port_range)
    
    # Détection de vulnérabilités
    detector = VulnerabilityDetector()
    vulnerabilities = detector.detect(open_ports)
    
    # Géolocalisation
    geo_lookup = GeolocationLookup()
    geo_info = geo_lookup.get_location(args.target)
    
    # Génération du rapport
    generator = ReportGenerator()
    report = generator.generate(args.target, open_ports, vulnerabilities, geo_info)
    
    print("\n" + "="*60)
    print("RÉSUMÉ DU SCAN")
    print("="*60)
    print(report)
    
    # Sauvegarde si demandée
    if args.output:
        generator.save_report(report, args.output)
    
    # Alertes de sécurité
    if vulnerabilities:
        print("\n[!] ALERTES DE SÉCURITÉ:")
        for vuln in vulnerabilities:
            print(f"    [{vuln['severity']}] Port {vuln['port']}: {vuln['description']}")


if __name__ == "__main__":
    main()
