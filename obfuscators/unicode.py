"""
Unicode Cloak Obfuscator
Bypasses: String pattern matching, signature detection
Technique: Zero-width spaces and invisible Unicode characters
"""

import random

class UnicodeObfuscator:
    def __init__(self):
        # Zero-width and invisible Unicode characters
        self.invisible_chars = [
            '\u200b',  # Zero Width Space
            '\u200c',  # Zero Width Non-Joiner
            '\u200d',  # Zero Width Joiner
            '\u2060',  # Word Joiner
            '\ufeff',  # Zero Width No-Break Space
        ]
        self.density = 0.3  # 30% chance to insert invisible char
    
    def randomize(self):
        """Randomize obfuscation parameters"""
        self.density = random.uniform(0.2, 0.6)
    
    def encode(self, payload):
        """Insert invisible Unicode characters"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        
        result = ""
        for i, char in enumerate(payload):
            result += char
            
            # Randomly insert invisible characters
            if random.random() < self.density:
                invisible = random.choice(self.invisible_chars)
                result += invisible
        
        return result
    
    def encode_advanced(self, payload):
        """Advanced Unicode obfuscation with homoglyphs"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        
        # Unicode homoglyphs (visually similar characters)
        homoglyphs = {
            'a': ['а', 'ɑ', 'α'],  # Cyrillic/Greek alternatives
            'e': ['е', 'ε'],
            'o': ['о', 'ο', '᧐'],
            'p': ['р', 'ρ'],
            'c': ['с', 'ϲ'],
            'x': ['х', 'χ'],
            'i': ['і', 'ι', 'ⅰ'],
            'j': ['ј'],
            's': ['ѕ', 'ς'],
            'y': ['у', 'γ'],
        }
        
        result = ""
        for char in payload:
            if char.lower() in homoglyphs and random.random() < 0.4:
                # Replace with homoglyph
                alternatives = homoglyphs[char.lower()]
                replacement = random.choice(alternatives)
                # Preserve case
                if char.isupper():
                    replacement = replacement.upper()
                result += replacement
            else:
                result += char
            
            # Still add invisible chars
            if random.random() < self.density:
                invisible = random.choice(self.invisible_chars)
                result += invisible
        
        return result
    
    def clean(self, obfuscated_payload):
        """Remove invisible characters for execution"""
        cleaned = obfuscated_payload
        for char in self.invisible_chars:
            cleaned = cleaned.replace(char, '')
        return cleaned