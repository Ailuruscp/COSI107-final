#!/usr/bin/env python3
"""
Network Analyzer for IoT Security Assessment
This script captures and analyzes network traffic from IoT devices.
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import pyshark
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
logger = logging.getLogger("network_analyzer")
console = Console()

class NetworkAnalyzer:
    def __init__(self, interface: str, output_dir: Path):
        self.interface = interface
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def start_capture(self, duration: int = 300) -> None:
        """Start capturing network traffic."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = self.output_dir / f"capture_{timestamp}.pcap"
        
        logger.info(f"Starting capture on interface {self.interface}")
        logger.info(f"Capture will be saved to {pcap_file}")
        
        try:
            capture = pyshark.LiveCapture(
                interface=self.interface,
                output_file=str(pcap_file)
            )
            capture.sniff(timeout=duration)
            logger.info("Capture completed successfully")
            self.analyze_capture(pcap_file)
        except Exception as e:
            logger.error(f"Error during capture: {e}")
            sys.exit(1)

    def analyze_capture(self, pcap_file: Path) -> None:
        """Analyze the captured traffic for security issues."""
        logger.info(f"Analyzing capture file: {pcap_file}")
        
        try:
            capture = pyshark.FileCapture(str(pcap_file))
            
            # Create tables for different types of findings
            unencrypted_traffic = Table(title="Unencrypted Traffic")
            unencrypted_traffic.add_column("Time")
            unencrypted_traffic.add_column("Source")
            unencrypted_traffic.add_column("Destination")
            unencrypted_traffic.add_column("Protocol")
            
            suspicious_ports = Table(title="Suspicious Port Activity")
            suspicious_ports.add_column("Time")
            suspicious_ports.add_column("Source")
            suspicious_ports.add_column("Destination")
            suspicious_ports.add_column("Port")
            
            for packet in capture:
                # Check for unencrypted HTTP traffic
                if hasattr(packet, 'http'):
                    unencrypted_traffic.add_row(
                        str(packet.sniff_time),
                        packet.ip.src,
                        packet.ip.dst,
                        "HTTP"
                    )
                
                # Check for suspicious ports
                if hasattr(packet, 'tcp'):
                    port = int(packet.tcp.dstport)
                    if port in [23, 445, 3389]:  # Common suspicious ports
                        suspicious_ports.add_row(
                            str(packet.sniff_time),
                            packet.ip.src,
                            packet.ip.dst,
                            str(port)
                        )
            
            # Display findings
            console.print(unencrypted_traffic)
            console.print(suspicious_ports)
            
        except Exception as e:
            logger.error(f"Error analyzing capture: {e}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="IoT Network Traffic Analyzer")
    parser.add_argument("--interface", required=True, help="Network interface to capture on")
    parser.add_argument("--duration", type=int, default=300, help="Capture duration in seconds")
    parser.add_argument("--output", type=Path, default=Path("captures"), help="Output directory for captures")
    
    args = parser.parse_args()
    
    analyzer = NetworkAnalyzer(args.interface, args.output)
    analyzer.start_capture(args.duration)

if __name__ == "__main__":
    main() 