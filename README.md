# 🔥 AKUMA'S ULTIMATE PENETRATION TESTING SCANNER v3.0 🔥

*"Один скрипт, чтобы Pwn3d их всех!"*

## 🚀 New in v3.0 - THE ULTIMATE BEAST!

### ⚡ Major Features Added:
- **118 NetExec modules** support - Full comprehensive testing
- **Credential validation** with Pwn3d detection  
- **Multi-protocol testing** (SMB/RDP/WinRM/MSSQL/SSH)
- **Automated exploitation guides** generation
- **Detailed HTML reports** with remediation steps
- **Checkpoint/resume** functionality for large scans
- **Enterprise-scale** configuration options

### 💀 What This Scanner Can Do:
- ✅ **Service Discovery** across 10+ protocols
- ✅ **Credential Testing** with real Pwn3d validation
- ✅ **118 Vulnerability Modules** from NetExec
- ✅ **Exploitation Guides** for every finding
- ✅ **Comprehensive Reports** (Executive + Technical)
- ✅ **Remediation Recommendations** 
- ✅ **Checkpoint Recovery** for interrupted scans

---

## 📦 Available Scanners

### 🔥 `ultimate_akuma_scanner.sh` (v3.0) - THE BEAST
**The ultimate penetration testing framework**
- 118 NetExec modules
- Multi-protocol credential testing
- Automated exploitation guides
- Enterprise-scale support

### ⚡ `advanced_lowhanging_scanner.sh` (v2.0)  
**Advanced vulnerability scanner**  
- Focused on critical vulnerabilities
- Checkpoint/resume functionality
- Detailed reporting

### 📋 `demo_scanner.sh` (Demo)
**Quick demonstration scanner**
- Basic service discovery
- Simple vulnerability checks

---

## 🎯 Installation & Usage

### Prerequisites
```bash
# Install NetExec
pip install netexec

# Install nmap (if not already installed)
sudo apt install nmap
```

### Quick Start - Ultimate Scanner
```bash
# Clone the repository
git clone https://github.com/sweetpotatohack/akuma-lowhanging-scanner.git
cd akuma-lowhanging-scanner

# Make executable
chmod +x ultimate_akuma_scanner.sh

# Basic scan
./ultimate_akuma_scanner.sh --subnet 192.168.1.0/24

# Authenticated comprehensive scan
./ultimate_akuma_scanner.sh \
  --auth \
  --username pentester \
  --password "YourPassword" \
  --subnet 192.168.112.0/22
```

### Configuration Files
The scanner includes several pre-configured examples:
- `configs/ultimate_scanner_config.conf` - Default configuration
- `configs/enterprise_scale_config.conf` - Enterprise networks  
- `configs/windows_target_config.conf` - Windows-focused testing
- `configs/final_test_config.conf` - Comprehensive testing

---

## 🛡️ Vulnerability Modules Coverage

### 🔴 Critical Vulnerabilities (8 modules)
- **zerologon** - CVE-2020-1472 Domain Controller privilege escalation
- **ms17-010** - EternalBlue RCE (WannaCry/NotPetya fame)  
- **smbghost** - CVE-2020-0796 Windows 10 RCE
- **printnightmare** - CVE-2021-34527 Print Spooler RCE
- **petitpotam** - NTLM Relay attack vector
- **nopac** - Domain Controller exploitation
- **shadowcoerce** - Authentication coercion
- **dfscoerce** - DFS coercion attacks

### 🟠 High Priority (9 modules)  
- **lsassy** - LSASS memory dumping
- **nanodump** - Advanced LSASS dumping
- **handlekatz** - Handle-based credential extraction
- **ntds-dump-raw** - NTDS.dit extraction
- **procdump** - Process memory dumping
- **masky** - Credential harvesting
- **dpapi_hash** - DPAPI secrets extraction
- **backup_operator** - Backup operators abuse

### 🟡 Credential Harvesting (10 modules)
- **gpp_password** - Group Policy Preferences passwords
- **gpp_autologin** - Autologin credentials  
- **laps** - Local Administrator Password Solution
- **keepass_discover** - KeePass database discovery
- **hash_spider** - Credential hash collection
- **powershell_history** - PowerShell command history
- **wifi** - Wireless credentials extraction
- **teams_localdb** - Microsoft Teams tokens

### 🔵 Enumeration (13 modules)
- **enum_trusts** - Active Directory trust enumeration
- **enum_dns** - DNS configuration analysis
- **enum_ca** - Certificate Authority enumeration
- **enum_av** - Antivirus detection
- **get-desc-users** - User description harvesting
- **group-mem** - Group membership analysis
- **find-computer** - Computer discovery
- **subnets** - Network enumeration

### ⚪ Additional (78+ more modules)
Complete coverage of NetExec's 118 modules including:
- ADCS attacks, Pre2K vulnerabilities, MSSQL exploitation
- Browser credential extraction, Registry analysis
- Privilege escalation vectors, Persistence mechanisms
- And many more...

---

## 📊 Real Penetration Testing Results

### 🎯 Example Scan Results (192.168.112.0/22):
- **Total hosts scanned:** 1024
- **Services discovered:** 190+ responsive hosts
- **PWN3D hosts:** 15 successful authentications
- **Protocols compromised:** SMB, RDP, WinRM
- **Domain identified:** astralnalog.ru
- **Scan duration:** 25 minutes

### 📁 Output Structure
```
ultimate_scan_results/scan_YYYYMMDD_HHMMSS/
├── 📁 credentials/          # Credential testing logs
├── 📁 exploitation/         # Exploitation guides per finding
├── 📁 logs/                 # Detailed module execution logs  
├── 📁 raw_results/          # Raw nmap/discovery results
├── 📁 results/              # Parsed vulnerability findings
├── 📁 reports/              # Generated reports
├── 📄 pwned_hosts.txt       # Successfully compromised hosts
├── 📄 CRITICAL_FINDINGS.txt # Critical vulnerabilities found
├── 📄 ULTIMATE_PENTEST_REPORT.md # Technical report  
├── 📄 EXECUTIVE_SUMMARY.txt # Executive summary
└── 📄 ultimate_scanner.log  # Complete scan log
```

---

## 🎯 Usage Examples

### Basic Network Scan
```bash
./ultimate_akuma_scanner.sh --subnet 192.168.1.0/24
```

### Authenticated Comprehensive Scan
```bash
./ultimate_akuma_scanner.sh \
  --auth \
  --username "ideco" \
  --password "hjl100gфывфывфыап" \
  --subnet 192.168.112.0/22 \
  --debug
```

### Enterprise Network Scan
```bash  
./ultimate_akuma_scanner.sh \
  --config configs/enterprise_scale_config.conf \
  --auth \
  --username "domain_user" \
  --password "complex_password"
```

### Targeted Windows Environment  
```bash
./ultimate_akuma_scanner.sh \
  --subnet 172.16.0.0/16 \
  --username administrator \
  --password "Admin123!" \
  --domain CORP
```

---

## ⚠️ Ethical Usage & Disclaimer

**🚨 IMPORTANT: This tool is for AUTHORIZED PENETRATION TESTING ONLY!**

### Legal Usage
- ✅ Authorized penetration testing
- ✅ Red team exercises  
- ✅ Security assessments on owned infrastructure
- ✅ Educational/training purposes in lab environments

### Prohibited Usage  
- ❌ Unauthorized access to systems
- ❌ Malicious attacks on third-party infrastructure
- ❌ Any illegal or unethical activities

**The developers are NOT responsible for misuse of this tool.**

---

## 🔧 Advanced Configuration

### Performance Tuning
```bash
# High-performance enterprise scanning
MAX_PARALLEL=50
NMAP_THREADS=500  
TIMEOUT_PER_HOST=90

# Conservative resource usage  
MAX_PARALLEL=10
NMAP_THREADS=100
TIMEOUT_PER_HOST=180
```

### Reliability Features
```bash
# Enable checkpointing for large scans
RESUME_SCAN=true
CHECKPOINT_INTERVAL=50
AUTO_RETRY_FAILED=true
MAX_RETRY_ATTEMPTS=3
```

---

## 📈 Version History

### v3.0 (Current) - Ultimate Edition
- 118 NetExec modules integration
- Multi-protocol credential validation  
- Automated exploitation guide generation
- Enterprise-scale configuration options
- Comprehensive reporting framework

### v2.0 - Advanced Edition  
- 25+ critical vulnerability modules
- Checkpoint/resume functionality
- Advanced reporting capabilities
- Error handling and retry mechanisms

### v1.0 - Initial Release
- Basic service discovery
- Core vulnerability detection  
- Simple reporting

---

## 🤝 Contributing

Feel free to contribute to this project:
1. Fork the repository
2. Create feature branch
3. Submit pull request

### Feature Requests
- Additional NetExec modules integration
- Custom vulnerability checks
- Enhanced reporting formats
- Performance optimizations

---

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🔥 Credits

Created by **AKUMA** - *Legendary hacker and microservices guru*

*"С такой защитой ваша инфраструктура безопаснее, чем сейф из картона!"*

**🔥 "Один скрипт, чтобы Pwn3d их всех!" 🔥**
