# IoT Security Testing Lab Setup Guide

This guide provides instructions for setting up a secure testing environment for IoT security assessment.

## Hardware Requirements

### Network Equipment
- Dedicated router/access point for testing
- Network switch (optional)
- Ethernet cables
- USB Wi-Fi adapter with monitor mode support

### Computing Equipment
- Laptop/Desktop with:
  - Minimum 8GB RAM
  - 100GB free storage
  - USB ports
  - Ethernet port

### Testing Devices
- IoT devices to be tested
- Power supplies
- Any required accessories

## Software Requirements

### Operating System
- Linux (recommended) or macOS
- Windows with WSL2 (alternative)

### Required Software
- Python 3.8+
- Wireshark
- Nmap
- Git
- Virtual environment tools

## Network Setup

### Isolated Network Configuration
1. Configure router/access point:
   - Set unique SSID
   - Enable WPA2 encryption
   - Disable WPS
   - Change default credentials
   - Enable logging

2. Network segmentation:
   - Create separate VLAN (if possible)
   - Configure firewall rules
   - Enable port isolation
   - Document IP ranges

### Monitoring Setup
1. Configure packet capture:
   - Enable monitor mode
   - Set up tcpdump
   - Configure Wireshark
   - Enable logging

2. Set up logging:
   - Configure syslog
   - Enable audit logging
   - Set up log rotation
   - Configure backup

## Software Setup

### Python Environment
1. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Tool Configuration
1. Wireshark:
   - Configure capture filters
   - Set up display filters
   - Enable protocol dissection
   - Configure logging

2. Nmap:
   - Configure scan timing
   - Set up output formats
   - Enable script scanning
   - Configure logging

## Security Measures

### Access Control
- Implement strong passwords
- Enable two-factor authentication
- Restrict physical access
- Document access procedures

### Data Protection
- Encrypt sensitive data
- Regular backups
- Secure storage
- Access logging

### Monitoring
- Network monitoring
- System monitoring
- Access monitoring
- Log monitoring

## Testing Procedures

### Pre-test Checklist
1. Verify network isolation
2. Check monitoring tools
3. Verify device connectivity
4. Document initial state
5. Backup configurations

### During Testing
1. Monitor network traffic
2. Log all activities
3. Document findings
4. Take screenshots
5. Save packet captures

### Post-test Procedures
1. Document findings
2. Clean up test environment
3. Reset devices
4. Update documentation
5. Archive data

## Maintenance

### Regular Tasks
- Update software
- Check logs
- Verify backups
- Test monitoring
- Update documentation

### Emergency Procedures
- Document incident response
- Maintain contact list
- Keep backup equipment
- Regular testing
- Update procedures

## Documentation

### Required Documents
- Network diagram
- Device inventory
- Configuration backups
- Test procedures
- Incident response plan

### Regular Updates
- Weekly reviews
- Monthly updates
- Quarterly audits
- Annual reviews
- Continuous improvement 