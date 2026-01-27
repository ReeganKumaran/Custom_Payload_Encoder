"""
ROT13 Encoder
Bypasses: Simple string matching, basic obfuscation
Technique: Character rotation with custom offset
"""

import random
import string

class ROT13Encoder:
    def __init__(self):
        self.offset = 13
        self.custom_charset = False
    
    def randomize(self):
        """Randomize ROT parameters"""
        self.offset = random.randint(1, 25)
        self.custom_charset = random.choice([True, False])
    
    def encode(self, payload):
        """Apply ROT encoding"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        
        result = ""
        for char in payload:
            if char.isalpha():
                # Determine if uppercase or lowercase
                base = ord('A') if char.isupper() else ord('a')
                # Apply rotation
                rotated = (ord(char) - base + self.offset) % 26
                result += chr(base + rotated)
            elif self.custom_charset and char.isdigit():
                # Rotate digits too
                rotated = (int(char) + self.offset) % 10
                result += str(rotated)
            else:
                result += char
        
        return result
    
    def decode(self, encoded_payload):
        """Decode ROT encoded payload"""
        result = ""
        for char in encoded_payload:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                # Reverse rotation
                rotated = (ord(char) - base - self.offset) % 26
                result += chr(base + rotated)
            elif self.custom_charset and char.isdigit():
                rotated = (int(char) - self.offset) % 10
                result += str(rotated)
            else:
                result += char
        
        return result