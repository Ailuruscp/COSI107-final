#!/usr/bin/env python3
"""
Security Scanner for IoT Security Assessment
This script performs comprehensive security scans of IoT devices.
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import nmap
import requests
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("security_scanner")
console = Console()

class SecurityScanner:
    def __init__(self, target: str, output_dir: Path):
        self.target = target
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings: List[Dict] = []
        self.nm = nmap.PortScanner()
        
    def run_scan(self) -> None:
        """Run a comprehensive security scan."""
        logger.info(f"Starting security scan of {self.target}")
        
        # Perform various scans
        self._scan_ports()
        self._check_web_interface()
        self._check_common_vulnerabilities()
        self._display_findings()
        
    def _scan_ports(self) -> None:
        """Scan for open ports and services."""
        try:
            # Perform a TCP SYN scan
            self.nm.scan(self.target, arguments='-sS -sV -p-')
            
            if self.target in self.nm.all_hosts():
                for proto in self.nm[self.target].all_protocols():
                    ports = self.nm[self.target][proto].keys()
                    for port in ports:
                        service = self.nm[self.target][proto][port]
                        self.findings.append({
                            "type": "Port Scan",
                            "description": f"Port {port}/{proto}: {service['name']} {service['version']}",
                            "severity": "Medium" if port in [80, 443] else "High"
                        })
        except Exception as e:
            logger.error(f"Error during port scan: {e}")
            
    def _check_web_interface(self) -> None:
        """Check for web interface vulnerabilities."""
        try:
            # Check HTTP
            response = requests.get(f"http://{self.target}", timeout=5)
            if response.status_code == 200:
                self.findings.append({
                    "type": "Web Interface",
                    "description": "HTTP interface accessible (unencrypted)",
                    "severity": "High"
                })
                
            # Check HTTPS
            try:
                response = requests.get(f"https://{self.target}", timeout=5)
                if response.status_code == 200:
                    self.findings.append({
                        "type": "Web Interface",
                        "description": "HTTPS interface accessible",
                        "severity": "Low"
                    })
            except requests.exceptions.SSLError:
                self.findings.append({
                    "type": "Web Interface",
                    "description": "HTTPS certificate issues",
                    "severity": "Medium"
                })
        except requests.exceptions.RequestException:
            pass
            
    def _check_common_vulnerabilities(self) -> None:
        """Check for common IoT vulnerabilities."""
        try:
            # Check for default credentials
            default_credentials = [
                ("admin", "admin"),
                ("root", "root"),
                ("admin", "password"),
            ]
            
            for username, password in default_credentials:
                try:
                    response = requests.get(
                        f"http://{self.target}",
                        auth=(username, password),
                        timeout=5
                    )
                    if response.status_code == 200:
                        self.findings.append({
                            "type": "Vulnerability",
                            "description": f"Default credentials work: {username}:{password}",
                            "severity": "Critical"
                        })
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            logger.error(f"Error checking vulnerabilities: {e}")
            
    def _display_findings(self) -> None:
        """Display all findings in a formatted table."""
        table = Table(title="Security Scan Findings")
        table.add_column("Type")
        table.add_column("Description")
        table.add_column("Severity")
        
        for finding in self.findings:
            table.add_row(
                finding["type"],
                finding["description"],
                finding["severity"]
            )
            
        console.print(table)
        
        # Save findings to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"scan_{self.target}_{timestamp}.txt"
        
        with open(output_file, 'w') as f:
            f.write("Security Scan Findings\n")
            f.write("=====================\n\n")
            for finding in self.findings:
                f.write(f"Type: {finding['type']}\n")
                f.write(f"Description: {finding['description']}\n")
                f.write(f"Severity: {finding['severity']}\n")
                f.write("-" * 50 + "\n")
                
        logger.info(f"Scan results saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="IoT Security Scanner")
    parser.add_argument("--target", required=True, help="Target device IP address")
    parser.add_argument("--output", type=Path, default=Path("scan_results"), help="Output directory for scan results")
    
    args = parser.parse_args()
    
    scanner = SecurityScanner(args.target, args.output)
    scanner.run_scan()

if __name__ == "__main__":
    main() 