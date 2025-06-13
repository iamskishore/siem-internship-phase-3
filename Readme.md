#  SIEM Internship – Phase 3:  Advanced Threat Hunting & APT Simulation

## Objective:

 To simulate complex attack scenarios mimicking **Advanced Persistent Threats (APT)** and train candidates to:
- **Detect** stealthy and evasive attacks using real-world tools.
- **Analyze** attacker behavior through event correlation and forensic investigation.
- **Respond** effectively using a layered defense strategy that combines endpoint monitoring, network visibility, and rule-based detection.
## Tools Used

- Windows Virtual Machine (VM) in AWS(EC2)
- **Sysmon** – System Monitor for Sysinternals
- Elastic Stack (Elasticsearch + Kibana + Logstash)
- Elastic Agent 

##  Use Cases

### Fileless Malware with PowerShell

- Simulates spear-phishing leading to PowerShell-based payloads.
- Detection through obfuscated scripts, encoded commands.

 [`Fileless Malware with PowerShell`](writeups/Use%20Case%201%20Fileless%20Malware%20with%20PowerShell/Readme.md)

###  Lateral Movement via RDP Brute Force

- Attackers use stolen credentials to brute-force RDP across servers.
- Detect failed/successful Event ID 4625/4624.

 [`Lateral Movement via RDP Brute Force`](writeups/Use%20Case%202%20Lateral%20Movement%20via%20RDP%20Brute%20Force/Readme.md)
### Persistence via Registry Run Keys

- Persistence via malicious registry key (e.g. `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).

 [`Persistence via Registry Run Keys`](writeups/Use%20Case%203%20Persistence%20via%20Registry%20Run%20Keys/Readme.md)

### DNS Tunneling (Data Exfiltration)

- Exfiltration using DNS queries (e.g., base64-encoded in subdomains).
- Use Suricata/Zeek to analyze traffic.

[`DNS Tunneling - Data exfiltration`](writeups/Use%20Case%204%20.%20DNS%20Tunneling%20-%20Data%20exfiltration/Readme.md)

### Credential Dumping and Exfiltration (Mimikatz)

- Simulates Mimikatz usage to dump LSASS.
- Exfiltration over HTTPS or SMB.

 [`Credential Dumping and Exfiltration - Mimikatz`](writeups/Use%20Case%205%20%20Credential%20Dumping%20and%20Exfiltration%20-%20Mimikatz/Readme.md)

##  Goals
- Advanced Threat Hunting
- SIEM Rule Writing & Detection
- MITRE ATT&CK Mapping
- Red-Blue Teaming Foundation



