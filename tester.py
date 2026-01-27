"""
Detection Engine Tester
Simulates: AV, EDR, WAF, and Falco detection engines
Purpose: Test payload evasion effectiveness
"""

import re
import random

class DetectionTester:
    def __init__(self):
        # Signature databases for different security tools
        self.av_signatures = [
            'whoami', 'netstat', 'powershell.exe', 'cmd.exe', 'bash',
            'wget', 'curl', 'nc', 'ncat', 'telnet'
        ]
        
        self.edr_signatures = [
            'base64', 'memory_exec', r'\x00\x01', 'shellcode',
            'CreateProcess', 'VirtualAlloc', 'WriteProcessMemory'
        ]
        
        self.waf_signatures = [
            '<script>', 'union select', 'exec(', 'eval(',
            'javascript:', 'onload=', 'onerror=', '../'
        ]
        
        self.falco_signatures = [
            'id', '/bin/bash', '/bin/sh', 'sudo', 'su',
            'passwd', 'shadow', '/etc/', '/proc/'
        ]
        
        # Behavioral patterns
        self.behavioral_patterns = [
            r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64 pattern
            r'\\x[0-9a-fA-F]{2}',         # Hex encoding
            r'%[0-9a-fA-F]{2}',           # URL encoding
            r'&#x[0-9a-fA-F]+;',          # HTML entity
        ]
    
    def test_payload(self, payload):
        """Test payload against all detection engines"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8', errors='ignore')
        
        detections = 0
        total_tests = 0
        
        # Test against each engine
        av_result = self._test_av(payload)
        edr_result = self._test_edr(payload)
        waf_result = self._test_waf(payload)
        falco_result = self._test_falco(payload)
        behavioral_result = self._test_behavioral(payload)
        
        # Calculate evasion score
        results = [av_result, edr_result, waf_result, falco_result, behavioral_result]
        evasion_score = (sum(results) / len(results)) * 100
        
        return int(evasion_score)
    
    def _test_av(self, payload):
        """Test against AV signatures"""
        payload_lower = payload.lower()
        detections = 0
        
        for signature in self.av_signatures:
            if signature.lower() in payload_lower:
                detections += 1
        
        # Return evasion rate (0 = all detected, 1 = none detected)
        return max(0, 1 - (detections / len(self.av_signatures)))
    
    def _test_edr(self, payload):
        """Test against EDR signatures"""
        detections = 0
        
        for signature in self.edr_signatures:
            if re.search(signature, payload, re.IGNORECASE):
                detections += 1
        
        return max(0, 1 - (detections / len(self.edr_signatures)))
    
    def _test_waf(self, payload):
        """Test against WAF signatures"""
        payload_lower = payload.lower()
        detections = 0
        
        for signature in self.waf_signatures:
            if signature in payload_lower:
                detections += 1
        
        return max(0, 1 - (detections / len(self.waf_signatures)))
    
    def _test_falco(self, payload):
        """Test against Falco (container security) signatures"""
        detections = 0
        
        for signature in self.falco_signatures:
            if signature in payload:
                detections += 1
        
        return max(0, 1 - (detections / len(self.falco_signatures)))
    
    def _test_behavioral(self, payload):
        """Test against behavioral patterns"""
        detections = 0
        
        for pattern in self.behavioral_patterns:
            if re.search(pattern, payload):
                detections += 1
        
        return max(0, 1 - (detections / len(self.behavioral_patterns)))
    
    def test_av_engines(self, payload):
        """Detailed AV engine testing"""
        engines = {
            'Windows Defender': self._test_windows_defender,
            'ClamAV': self._test_clamav,
            'Kaspersky': self._test_kaspersky,
            'Norton': self._test_norton,
            'McAfee': self._test_mcafee
        }
        
        results = {}
        for engine_name, test_func in engines.items():
            result = test_func(payload)
            status = "✅ CLEAN" if result > 0.7 else "⚠️ SUSPICIOUS" if result > 0.3 else "❌ DETECTED"
            results[engine_name] = {
                'score': result,
                'status': status
            }
            print(f"{engine_name}: {int(result * 100)}% evasion {status}")
        
        return results
    
    def _test_windows_defender(self, payload):
        """Simulate Windows Defender detection"""
        defender_sigs = ['powershell', 'amsi', 'invoke-expression', 'downloadstring']
        return self._generic_signature_test(payload, defender_sigs)
    
    def _test_clamav(self, payload):
        """Simulate ClamAV detection"""
        clam_sigs = ['base64', 'shell', 'exec', 'system']
        return self._generic_signature_test(payload, clam_sigs)
    
    def _test_kaspersky(self, payload):
        """Simulate Kaspersky detection"""
        kaspersky_sigs = ['malware', 'trojan', 'backdoor', 'exploit']
        return self._generic_signature_test(payload, kaspersky_sigs)
    
    def _test_norton(self, payload):
        """Simulate Norton detection"""
        norton_sigs = ['suspicious', 'heuristic', 'behavior']
        return self._generic_signature_test(payload, norton_sigs)
    
    def _test_mcafee(self, payload):
        """Simulate McAfee detection"""
        mcafee_sigs = ['virus', 'worm', 'rootkit']
        return self._generic_signature_test(payload, mcafee_sigs)
    
    def _generic_signature_test(self, payload, signatures):
        """Generic signature testing"""
        payload_lower = payload.lower()
        detections = sum(1 for sig in signatures if sig in payload_lower)
        return max(0, 1 - (detections / len(signatures)))
    
    def generate_detection_report(self, payload, variants):
        """Generate comprehensive detection report"""
        report = {
            'payload': payload,
            'total_variants': len(variants),
            'detection_summary': {},
            'best_variant': None,
            'recommendations': []
        }
        
        # Test each variant
        for variant in variants:
            score = self.test_payload(variant['payload'])
            variant['detection_score'] = score
        
        # Find best variant
        best = max(variants, key=lambda x: x.get('detection_score', 0))
        report['best_variant'] = best
        
        # Generate recommendations
        if best['detection_score'] < 50:
            report['recommendations'].append("Consider additional obfuscation layers")
        if best['detection_score'] < 70:
            report['recommendations'].append("Add more randomization to bypass heuristics")
        if best['detection_score'] > 90:
            report['recommendations'].append("Excellent evasion - ready for deployment")
        
        return report