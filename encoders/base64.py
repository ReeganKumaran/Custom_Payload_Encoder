"""
Base64 Armor Encoder
Bypasses: Basic string detection, simple pattern matching
Technique: Multi-layer base64 with padding manipulation
"""

import base64
import random
import string

class Base64Encoder:
    def __init__(self):
        self.iterations = 2
        self.custom_padding = True
    
    def randomize(self):
        """Randomize encoding parameters"""
        self.iterations = random.randint(1, 3)
        self.custom_padding = random.choice([True, False])
    
    def encode(self, payload):
        """Apply base64 armor with multiple layers"""
        result = payload.encode('utf-8')
        
        # Multiple base64 iterations
        for _ in range(self.iterations):
            result = base64.b64encode(result)
        
        # Custom padding manipulation
        if self.custom_padding:
            result = self._manipulate_padding(result.decode())
        else:
            result = result.decode()
        
        return result
    
    def _manipulate_padding(self, encoded):
        """Manipulate base64 padding to avoid detection"""
        # Remove standard padding
        clean = encoded.rstrip('=')
        
        # Add custom padding with random chars
        padding_chars = random.choices(string.ascii_letters + string.digits, k=2)
        return clean + ''.join(padding_chars)
    
    def decode(self, encoded_payload):
        """Decode base64 armored payload"""
        # Restore standard padding
        if self.custom_padding:
            # Remove custom padding and restore =
            clean = encoded_payload[:-2]
            missing_padding = len(clean) % 4
            if missing_padding:
                clean += '=' * (4 - missing_padding)
        else:
            clean = encoded_payload
        
        # Decode multiple iterations
        result = clean.encode()
        for _ in range(self.iterations):
            result = base64.b64decode(result)
        
        return result.decode('utf-8')