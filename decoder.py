#!/usr/bin/env python3
"""
Payload Decoder - Reverses obfuscation layers
"""

import base64
import re

class PayloadDecoder:
    def __init__(self):
        self.xor_key = "cyber"  # Default XOR key
    
    def decode_unicode(self, payload):
        """Remove zero-width unicode characters"""
        # Remove common zero-width characters
        cleaned = payload.replace('\u200b', '')  # Zero-width space
        cleaned = cleaned.replace('\u200c', '')  # Zero-width non-joiner
        cleaned = cleaned.replace('\u200d', '')  # Zero-width joiner
        cleaned = cleaned.replace('\ufeff', '')  # Zero-width no-break space
        return cleaned
    
    def decode_base64(self, payload):
        """Decode base64 (handles multiple layers)"""
        try:
            # Try multiple base64 decoding iterations
            result = payload
            for _ in range(5):  # Max 5 layers
                try:
                    decoded = base64.b64decode(result).decode('utf-8')
                    if decoded != result:
                        result = decoded
                    else:
                        break
                except:
                    break
            return result
        except:
            return payload
    
    def decode_xor(self, payload):
        """Decode XOR encryption"""
        try:
            if isinstance(payload, str):
                payload = payload.encode('latin1')
            
            decoded = bytes([b ^ ord(self.xor_key[i % len(self.xor_key)]) 
                           for i, b in enumerate(payload)])
            return decoded.decode('latin1')
        except:
            return payload
    
    def decode_junk(self, payload):
        """Remove junk characters (keep only original pattern)"""
        # Remove inserted numbers and random characters
        # This is a simplified approach - in real implementation, 
        # you'd need to store the junk pattern
        cleaned = re.sub(r'[0-9]+', '', payload)  # Remove numbers
        return cleaned
    
    def decode_fragment(self, payload):
        """Extract payload from fragment wrapper"""
        # Extract content from frag_data = """..."""
        match = re.search(r'frag_data = """(.+?)"""', payload, re.DOTALL)
        if match:
            return match.group(1)
        return payload
    
    def full_decode(self, obfuscated_payload):
        """Decode payload through all layers in reverse order"""
        result = obfuscated_payload
        
        print(f"🔄 Starting decode process...")
        print(f"📥 Input: {result[:50]}...")
        
        # Reverse the encoding order
        steps = [
            ("Fragment", self.decode_fragment),
            ("Junk", self.decode_junk),
            ("XOR", self.decode_xor),
            ("Base64", self.decode_base64),
            ("Unicode", self.decode_unicode)
        ]
        
        for step_name, decode_func in steps:
            old_result = result
            result = decode_func(result)
            if result != old_result:
                print(f"✅ {step_name} decoded: {result[:30]}...")
            else:
                print(f"⏭️  {step_name} skipped (no change)")
        
        print(f"🎯 Final result: {result}")
        return result

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        decoder = PayloadDecoder()
        with open(sys.argv[1], 'r') as f:
            content = f.read()
        
        # Extract the obfuscated payload
        match = re.search(r'frag_data = """(.+?)"""', content, re.DOTALL)
        if match:
            obfuscated = match.group(1)
            print("🔍 Found obfuscated payload, decoding...")
            decoded = decoder.full_decode(obfuscated)
        else:
            print("❌ No obfuscated payload found in file")
    else:
        print("Usage: python3 decoder.py <encoded_payload_file>")