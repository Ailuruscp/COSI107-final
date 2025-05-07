#!/usr/bin/env python3
"""
Firmware Security Checker for IoT Security Assessment
This script analyzes firmware files for common security issues.
"""

import argparse
import hashlib
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

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
logger = logging.getLogger("firmware_checker")
console = Console()

class FirmwareChecker:
    def __init__(self, firmware_path: Path):
        self.firmware_path = firmware_path
        self.findings: List[Dict] = []
        self.output_dir = Path("scan_results/firmware_analysis")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def check_firmware(self) -> None:
        """Perform security checks on the firmware file."""
        if not self.firmware_path.exists():
            logger.error(f"Firmware file not found: {self.firmware_path}")
            sys.exit(1)
            
        logger.info(f"Analyzing firmware: {self.firmware_path}")
        
        # Perform various checks
        self._check_file_size()
        self._check_file_hash()
        self._check_common_vulnerabilities()
        self._display_findings()
        self._save_findings()
        
    def _check_file_size(self) -> None:
        """Check if firmware size is reasonable."""
        size_mb = self.firmware_path.stat().st_size / (1024 * 1024)
        if size_mb > 100:  # Arbitrary threshold
            self.findings.append({
                "type": "Warning",
                "description": f"Large firmware size: {size_mb:.2f}MB",
                "severity": "Medium"
            })
            
    def _check_file_hash(self) -> None:
        """Calculate and store file hashes."""
        try:
            with open(self.firmware_path, 'rb') as f:
                content = f.read()
                md5 = hashlib.md5(content).hexdigest()
                sha256 = hashlib.sha256(content).hexdigest()
                
            self.findings.append({
                "type": "Info",
                "description": f"MD5: {md5}",
                "severity": "Low"
            })
            self.findings.append({
                "type": "Info",
                "description": f"SHA256: {sha256}",
                "severity": "Low"
            })
        except Exception as e:
            logger.error(f"Error calculating hashes: {e}")
            
    def _check_common_vulnerabilities(self) -> None:
        """Check for common firmware vulnerabilities."""
        # Check for hardcoded credentials
        try:
            with open(self.firmware_path, 'rb') as f:
                content = f.read()
                # Look for common patterns
                patterns = [
                    b'admin:admin',
                    b'root:root',
                    b'password',
                    b'default',
                ]
                
                for pattern in patterns:
                    if pattern in content:
                        self.findings.append({
                            "type": "Vulnerability",
                            "description": f"Potential hardcoded credentials found: {pattern.decode()}",
                            "severity": "High"
                        })
        except Exception as e:
            logger.error(f"Error checking for vulnerabilities: {e}")
            
    def _display_findings(self) -> None:
        """Display all findings in a formatted table."""
        table = Table(title="Firmware Analysis Findings")
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

    def _save_findings(self) -> None:
        """Save findings to a markdown file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"firmware_report_{timestamp}.md"
        
        with open(output_file, 'w') as f:
            f.write(f"# Firmware Analysis Report\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d')}\n\n")
            
            f.write("## Analysis Details\n")
            f.write(f"- Firmware File: {self.firmware_path.name}\n")
            f.write(f"- Analysis Tool: firmware_checker.py\n")
            f.write(f"- Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Findings\n")
            for finding in self.findings:
                f.write(f"### {finding['type']}\n")
                f.write(f"- Description: {finding['description']}\n")
                f.write(f"- Severity: {finding['severity']}\n\n")
            
            f.write("## Recommendations\n")
            f.write("1. Firmware Security\n")
            f.write("   - Maintain hash values for future firmware verification\n")
            f.write("   - Implement regular firmware update checks\n")
            f.write("   - Consider implementing firmware signing for future updates\n\n")
            
            f.write("2. Best Practices\n")
            f.write("   - Store firmware backups securely\n")
            f.write("   - Document all firmware changes\n")
            f.write("   - Implement version control for firmware updates\n")
        
        logger.info(f"Analysis results saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="IoT Firmware Security Checker")
    parser.add_argument("firmware", type=Path, help="Path to firmware file")
    
    args = parser.parse_args()
    
    checker = FirmwareChecker(args.firmware)
    checker.check_firmware()

if __name__ == "__main__":
    main() 