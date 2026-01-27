"""
Junk Scatter Obfuscator
Bypasses: Signature-based detection, pattern matching
Technique: Random character insertion with configurable density
"""

import random
import string

class JunkScatter:
    def __init__(self):
        self.density = 0.4  # 40% chance to insert junk
        self.junk_types = ['alpha', 'numeric', 'mixed']
        self.current_type = 'mixed'
    
    def randomize(self):
        """Randomize junk parameters"""
        self.density = random.uniform(0.2, 0.7)
        self.current_type = random.choice(self.junk_types)
    
    def encode(self, payload):
        """Insert random junk characters"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        
        result = ""
        for char in payload:
            result += char
            
            # Insert junk based on density
            if random.random() < self.density:
                junk_count = random.randint(1, 3)
                for _ in range(junk_count):
                    result += self._generate_junk()
        
        return result
    
    def _generate_junk(self):
        """Generate junk character based on type"""
        if self.current_type == 'alpha':
            return random.choice(string.ascii_letters)
        elif self.current_type == 'numeric':
            return random.choice(string.digits)
        else:  # mixed
            charset = string.ascii_letters + string.digits
            return random.choice(charset)
    
    def encode_contextual(self, payload):
        """Context-aware junk insertion"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        
        result = ""
        in_string = False
        quote_char = None
        
        for i, char in enumerate(payload):
            result += char
            
            # Track string context
            if char in ['"', "'"]:
                if not in_string:
                    in_string = True
                    quote_char = char
                elif char == quote_char:
                    in_string = False
                    quote_char = None
            
            # Insert junk based on context
            if not in_string and random.random() < self.density:
                # Outside strings - use comments or whitespace
                if payload[max(0, i-5):i+1].strip():  # Not at line start
                    junk = self._generate_comment_junk()
                else:
                    junk = self._generate_whitespace_junk()
                result += junk
            elif in_string and random.random() < (self.density * 0.3):
                # Inside strings - use escape sequences
                result += self._generate_escape_junk()
        
        return result
    
    def _generate_comment_junk(self):
        """Generate comment-based junk"""
        comments = [
            f"/*{self._generate_junk()}*/",
            f"//{self._generate_junk()}\n",
            f"#{self._generate_junk()}\n"
        ]
        return random.choice(comments)
    
    def _generate_whitespace_junk(self):
        """Generate whitespace junk"""
        spaces = random.randint(1, 4)
        return ' ' * spaces
    
    def _generate_escape_junk(self):
        """Generate escape sequence junk"""
        escapes = ['\\n', '\\t', '\\r', '\\ ']
        return random.choice(escapes)
    
    def clean(self, junked_payload):
        """Remove junk for execution (basic cleaning)"""
        # This is a simplified cleaner - real implementation would need
        # more sophisticated parsing based on the target language
        cleaned = junked_payload
        
        # Remove obvious junk patterns
        import re
        cleaned = re.sub(r'/\*[a-zA-Z0-9]*\*/', '', cleaned)
        cleaned = re.sub(r'//[a-zA-Z0-9]*\n', '\n', cleaned)
        cleaned = re.sub(r'#[a-zA-Z0-9]*\n', '\n', cleaned)
        
        return cleaned