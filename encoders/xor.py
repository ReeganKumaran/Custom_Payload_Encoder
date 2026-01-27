"""
XOR Encryption Encoder
Bypasses: Static signature detection, hash-based detection
Technique: Repeating key XOR with latin1 encoding (OverTheWire style)
"""

import random
import string

class XOREncoder:
    def __init__(self):
        self.key = "cyber"
        self.key_rotation = True
    
    def randomize(self):
        """Generate random XOR key"""
        key_length = random.randint(3, 8)
        self.key = ''.join(random.choices(string.ascii_lowercase, k=key_length))
        self.key_rotation = random.choice([True, False])
    
    def encode(self, payload):
        """XOR encode with repeating key"""
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        elif isinstance(payload, bytes):
            pass
        else:
            payload = str(payload).encode('utf-8')
        
        key_bytes = self.key.encode('utf-8')
        
        # XOR with repeating key
        xored = bytearray()
        for i, byte in enumerate(payload):
            key_byte = key_bytes[i % len(key_bytes)]
            if self.key_rotation:
                # Rotate key byte based on position
                key_byte = (key_byte + i) % 256
            xored.append(byte ^ key_byte)
        
        # Encode as latin1 string for transport
        return xored.decode('latin1')
    
    def decode(self, encoded_payload):
        """Decode XOR encrypted payload"""
        # Convert back to bytes
        payload_bytes = encoded_payload.encode('latin1')
        key_bytes = self.key.encode('utf-8')
        
        # XOR decode
        decoded = bytearray()
        for i, byte in enumerate(payload_bytes):
            key_byte = key_bytes[i % len(key_bytes)]
            if self.key_rotation:
                key_byte = (key_byte + i) % 256
            decoded.append(byte ^ key_byte)
        
        return decoded.decode('utf-8')
    
    def generate_decoder_stub(self):
        """Generate decoder stub for payload execution"""
        stub = f"""
key = "{self.key}"
rotation = {self.key_rotation}
def xor_decode(data):
    key_bytes = key.encode('utf-8')
    payload_bytes = data.encode('latin1')
    decoded = bytearray()
    for i, byte in enumerate(payload_bytes):
        key_byte = key_bytes[i % len(key_bytes)]
        if rotation:
            key_byte = (key_byte + i) % 256
        decoded.append(byte ^ key_byte)
    return decoded.decode('utf-8')
"""
        return stub