#!/usr/bin/env python3
"""
Unit Tests for Advanced Payload Framework
Tests encoding/decoding functionality
"""

import unittest
import tempfile
import os
import sys
import binascii

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encoder import PayloadEncoder
from payload_gen import PayloadGenerator

class TestPayloadEncoder(unittest.TestCase):
    def setUp(self):
        self.encoder = PayloadEncoder()
        self.test_data = b"Hello World Test Payload"
        self.test_string = "whoami && id"
    
    def test_base64_encoding(self):
        """Test Base64 encoding with multiple iterations"""
        encoded = self.encoder.encode_base64(self.test_data, 2)
        self.assertIsInstance(encoded, bytes)
        self.assertNotEqual(encoded, self.test_data)
        self.assertGreater(len(encoded), len(self.test_data))
    
    def test_xor_encoding_int_key(self):
        """Test XOR encoding with integer key"""
        key = 0xAA
        encoded = self.encoder.encode_xor(self.test_data, key)
        
        # Test decoding
        decoded = bytes([b ^ key for b in encoded])
        self.assertEqual(decoded, self.test_data)
    
    def test_xor_encoding_string_key(self):
        """Test XOR encoding with string key"""
        key = "secret"
        encoded = self.encoder.encode_xor(self.test_data, key)
        
        # Test decoding
        key_bytes = key.encode()
        decoded = bytes([encoded[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(encoded))])
        self.assertEqual(decoded, self.test_data)
    
    def test_caesar_encoding(self):
        """Test Caesar cipher encoding"""
        shift = 7
        encoded = self.encoder.encode_caesar(self.test_data, shift)
        
        # Test decoding
        decoded = bytes([(b - shift) % 256 for b in encoded])
        self.assertEqual(decoded, self.test_data)
    
    def test_rot13_encoding(self):
        """Test ROT13 encoding"""
        encoded = self.encoder.encode_rot13(self.test_data)
        self.assertIsInstance(encoded, bytes)
        self.assertNotEqual(encoded, self.test_data)
    
    def test_polymorphic_encoding(self):
        """Test polymorphic encoding"""
        encoded = self.encoder.encode_polymorphic(self.test_data)
        self.assertIsInstance(encoded, bytes)
        self.assertGreaterEqual(len(encoded), len(self.test_data))
        
        # Test that original bytes are still present
        nops = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97]
        decoded = bytes([b for b in encoded if b not in nops])
        self.assertEqual(decoded, self.test_data)
    
    def test_load_payload_binary(self):
        """Test loading binary payload"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(self.test_data)
            temp_file = f.name
        
        try:
            loaded = self.encoder.load_payload(temp_file, 'binary')
            self.assertEqual(loaded, self.test_data)
        finally:
            os.unlink(temp_file)
    
    def test_load_payload_hex(self):
        """Test loading hex payload"""
        hex_data = binascii.hexlify(self.test_data).decode()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(hex_data)
            temp_file = f.name
        
        try:
            loaded = self.encoder.load_payload(temp_file, 'hex')
            self.assertEqual(loaded, self.test_data)
        finally:
            os.unlink(temp_file)
    
    def test_load_payload_csharp(self):
        """Test loading C# format payload"""
        hex_bytes = [f"0x{b:02x}" for b in self.test_data]
        csharp_data = f"byte[] payload = new byte[{len(self.test_data)}] {{\n"
        csharp_data += "    " + ", ".join(hex_bytes) + "\n"
        csharp_data += "};"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(csharp_data)
            temp_file = f.name
        
        try:
            loaded = self.encoder.load_payload(temp_file, 'csharp')
            self.assertEqual(loaded, self.test_data)
        finally:
            os.unlink(temp_file)
    
    def test_decoder_stub_generation(self):
        """Test decoder stub generation"""
        encoded = self.encoder.encode_xor(self.test_data, 0xAA)
        decoder = self.encoder.generate_decoder_stub('xor', encoded, 0xAA)
        
        self.assertIsInstance(decoder, str)
        self.assertIn('decode_xor', decoder)
        self.assertIn('execute_shellcode', decoder)
        self.assertIn(binascii.hexlify(encoded).decode(), decoder)

class TestPayloadGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = PayloadGenerator()
    
    def test_python_reverse_generation(self):
        """Test Python reverse shell generation"""
        payload = self.generator.generate_python_reverse("127.0.0.1", "4444")
        self.assertIsInstance(payload, bytes)
        
        # Check for key components
        payload_str = payload.decode()
        self.assertIn("socket.socket", payload_str)
        self.assertIn("127.0.0.1", payload_str)
        self.assertIn("4444", payload_str)
        self.assertIn("subprocess", payload_str)
    
    def test_python_bind_generation(self):
        """Test Python bind shell generation"""
        payload = self.generator.generate_python_bind("8080")
        self.assertIsInstance(payload, bytes)
        
        payload_str = payload.decode()
        self.assertIn("bind", payload_str)
        self.assertIn("8080", payload_str)
        self.assertIn("listen", payload_str)
    
    def test_linux_reverse_generation(self):
        """Test Linux reverse shell generation"""
        payload = self.generator.generate_linux_reverse("192.168.1.1", "4444")
        self.assertIsInstance(payload, bytes)
        self.assertGreater(len(payload), 50)  # Should be substantial shellcode
    
    def test_linux_bind_generation(self):
        """Test Linux bind shell generation"""
        payload = self.generator.generate_linux_bind("8080")
        self.assertIsInstance(payload, bytes)
        self.assertGreater(len(payload), 50)
    
    def test_windows_reverse_generation(self):
        """Test Windows reverse shell generation"""
        payload = self.generator.generate_windows_reverse("10.0.0.1", "443")
        self.assertIsInstance(payload, bytes)
        self.assertGreater(len(payload), 100)
    
    def test_windows_bind_generation(self):
        """Test Windows bind shell generation"""
        payload = self.generator.generate_windows_bind("9999")
        self.assertIsInstance(payload, bytes)
        self.assertGreater(len(payload), 100)

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.encoder = PayloadEncoder()
        self.generator = PayloadGenerator()
    
    def test_full_pipeline(self):
        """Test complete generate -> encode -> decode pipeline"""
        # Generate payload
        original = self.generator.generate_python_reverse("127.0.0.1", "4444")
        
        # Encode with XOR
        encoded = self.encoder.encode_xor(original, 0xCC)
        
        # Decode
        decoded = bytes([b ^ 0xCC for b in encoded])
        
        # Verify
        self.assertEqual(original, decoded)
    
    def test_multiple_encoding_layers(self):
        """Test multiple encoding layers"""
        original = b"test payload for multiple layers"
        
        # Apply multiple encodings
        step1 = self.encoder.encode_caesar(original, 5)
        step2 = self.encoder.encode_xor(step1, 0x55)
        step3 = self.encoder.encode_base64(step2, 1)
        
        # Reverse the process manually
        import base64
        rev1 = base64.b64decode(step3)
        rev2 = bytes([b ^ 0x55 for b in rev1])
        rev3 = bytes([(b - 5) % 256 for b in rev2])
        
        self.assertEqual(original, rev3)

def run_tests():
    """Run all tests"""
    print("🧪 Running Advanced Payload Framework Tests")
    print("=" * 50)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestPayloadEncoder))
    suite.addTests(loader.loadTestsFromTestCase(TestPayloadGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    if result.wasSuccessful():
        print("✅ All tests passed!")
    else:
        print(f"❌ {len(result.failures)} failures, {len(result.errors)} errors")
        
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)