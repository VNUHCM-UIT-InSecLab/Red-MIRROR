from langchain_core.tools import tool
import subprocess
import os
import requests
import socket
import json
import paramiko
from urllib.parse import urlparse
from datetime import datetime
from pydantic import BaseModel, Field
from config.config import Configs
from typing import Dict, Optional, Literal, List
import shlex
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

# Import shared session state from exploit tool
from tools.web_exploit_tool import (
    mark_session_established, 
    check_login_success
)

TOOL_TIMEOUTS = {
    "whois": 10,
    "subfinder": 45,
    "assetfinder": 20,
    "dnsx": 25,
    "whatweb": 15,
    "http": 8,
    "crtsh": 12,
    "feroxbuster": 180,
}
MAX_SUBDOMAIN_RESULTS = 200
RECON_DIR = "recon_output"

class SSHExecutor:
    """Execute commands on remote Kali machine via SSH"""
    
    def __init__(self, hostname, port, username, password):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.client = None
    
    def connect(self):
        """Establish SSH connection"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10
            )
            return True
        except Exception as e:
            print(f"SSH Connection Error: {e}")
            return False
    
    def execute(self, cmd, timeout=30):
        """Execute command and return (returncode, stdout)"""
        try:
            if not self.client:
                if not self.connect():
                    return -1, f"Failed to connect to {self.hostname}"
            
            stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode('utf-8', errors='ignore')
            err = stderr.read().decode('utf-8', errors='ignore')
            
            returncode = stdout.channel.recv_exit_status()
            return returncode, out if out else err
            
        except subprocess.TimeoutExpired:
            return -1, f"TIMEOUT after {timeout}s"
        except Exception as e:
            return -3, str(e)
    
    def close(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()

# Get SSH config from basic_config.yaml
def _get_ssh_executor():
    """Get SSH executor from config"""
    try:
        kali_config = Configs.basic_config.kali
        executor = SSHExecutor(
            hostname=kali_config['hostname'],
            port=kali_config["port"],
            username=kali_config["username"],
            password=kali_config["password"]
        )
        return executor
    except Exception as e:
        print(f"Failed to load Kali config: {e}")
        return None

def parse_target(target):
    parsed = urlparse(target)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path.split('/')[0]
    base_url = f"{scheme}://{netloc}"
    domain_or_ip = netloc.split(":")[0]
    return base_url, domain_or_ip

def _ensure_outdir(domain):
    out = os.path.join(RECON_DIR, domain)
    os.makedirs(out, exist_ok=True)
    return out

def _safe_run_remote(cmd, timeout):
    """Run command on remote Kali machine"""
    executor = _get_ssh_executor()
    if not executor:
        return -3, "SSH executor not available"
    
    try:
        rc, out = executor.execute(cmd, timeout=timeout)
        executor.close()
        return rc, out
    except Exception as e:
        return -3, str(e)

class ReconInput(BaseModel):
    target: str

@tool(args_schema=ReconInput)
def whatweb_tool(target):
    """
    Web technology fingerprinting tool using WhatWeb on Kali Linux.
    
    PRIMARY USE: Identify web technologies, frameworks, CMS, server software, and potential vulnerabilities.
    
    Parameters:
    - target: Target URL (e.g., 'http://example.com' or 'http://192.168.1.1:8080')
    
    What WhatWeb Detects:
    - Web servers (Apache, Nginx, IIS, etc.)
    - CMS platforms (WordPress, Joomla, Drupal, etc.)
    - Programming languages (PHP, Python, Ruby, ASP.NET, etc.)
    - JavaScript frameworks (jQuery, React, Angular, Vue.js, etc.)
    - Analytics tools (Google Analytics, etc.)
    - Security headers and configurations
    - Version information for detected technologies
    - Cookies and session management details
    
    Returns:
    - Detailed fingerprint results including detected technologies, versions, and confidence levels
    - Results are saved to recon_output/<domain>/whatweb.txt
    
    Usage:
    - whatweb_tool(target="http://example.com")  # Basic fingerprinting
    - whatweb_tool(target="http://192.168.1.100:8080")  # Custom port
    
    WHEN TO USE:
    - At the beginning of reconnaissance to understand target's technology stack
    - Before exploitation to identify potential attack vectors
    - To detect outdated software versions with known vulnerabilities
    """
    _, domain = parse_target(target)
    outdir = _ensure_outdir(domain)
    outpath = os.path.join(outdir, "whatweb.txt")
    try:
        rc, out = _safe_run_remote(f"whatweb {target}", TOOL_TIMEOUTS["whatweb"])
        
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(out)
        return f"{out[:8000]}"
    except Exception as e:
        return f"WhatWeb error: {e}"

class CurlReconInput(BaseModel):
    url: str = Field(..., description="Full URL to scan/inspect, e.g. 'http://example.com/admin'")
    method: Literal["GET", "POST", "HEAD", "OPTIONS", "PUT"] = Field(
        default="GET", 
        description="HTTP method. HEAD/OPTIONS are useful for recon."
    )
    query_params: Optional[Dict[str, str]] = Field(
        default=None,
        description="Query parameters to append"
    )
    headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="Custom headers (e.g. User-Agent, X-Forwarded-For)"
    )
    cookies: Optional[Dict[str, str]] = Field(
        default=None,
        description="Cookies for authenticated recon"
    )
    body_type: Literal["none", "form", "json", "raw"] = "none"
    data: Optional[Dict[str, str]] = Field(
        default=None, 
        description="Data for form/json body"
    )
    raw_body: Optional[str] = None
    insecure_tls: bool = False
    timeout: int = 20
    include_headers: bool = Field(
        default=True,
        description="Include response headers in output (critical for recon)"
    )
    is_login: bool = Field(
        default=False,
        description="Set to True if this request is a login attempt. This will save cookies to the shared cookie jar."
    )
    is_time_based_injection: bool = Field(
        default=False,
        description="Set to True to measure response time for time-based vulnerability detection (blind SQLi, time-based RCE)"
    )

@tool(args_schema=CurlReconInput)
def curl_recon(
    url: str,
    method: str = "GET",
    query_params: dict | None = None,
    headers: dict | None = None,
    cookies: dict | None = None,
    body_type: str = "none",
    data: dict | None = None,
    raw_body: str | None = None,
    insecure_tls: bool = False,
    timeout: int = 20,
    include_headers: bool = True,
    is_login: bool = False,
    is_time_based_injection: bool = False,
):
    """
    Advanced reconnaissance tool for HTTP requests and response inspection.

    PRIMARY USE: Discover endpoints, forms, headers, cookies, and server behaviors during reconnaissance.

    Parameters:
    - url: Full URL to scan/inspect
    - method: HTTP method (GET/POST/HEAD/OPTIONS/PUT)
    - query_params: Query parameters dict
    - headers: Custom headers dict
    - cookies: Cookies dict
    - body_type: "none" | "form" | "json" | "raw"
    - data: Data dict (for form/json body)
    - raw_body: Raw string (for raw body)
    - include_headers: Include response headers (default: True, critical for recon)
    - is_login: Set True if this is a login attempt to save cookies
    - is_time_based_injection: Set True to measure response time for time-based vulnerability detection

    COOKIE MANAGEMENT:
    - All requests auto-load cookies from /tmp/pentest_cookies.txt
    - Set is_login=True on login POST to save new session cookies
    - Subsequent requests will use saved cookies automatically

    Returns:
    - Response with headers, body, cookie status, and duration (if is_time_based_injection=True)

    Usage:
    - curl_recon(url="http://target.com/admin", method="GET")  # Discover endpoint
    - curl_recon(url="/login", method="POST", body_type="form", data={"user": "admin", "pass": "admin"}, is_login=True)  # Login
    - curl_recon(url="/api/data", method="POST", body_type="json", data={"id": 1})  # JSON request
    - curl_recon(url="/search?q=test' AND SLEEP(5)--", is_time_based_injection=True)  # Time-based SQLi test
    """
    try:
        # 1) Handle Query Params
        if query_params:
            parsed = urlparse(url)
            existing_qs = dict(parse_qsl(parsed.query))
            existing_qs.update(query_params)
            new_query = urlencode(existing_qs)
            url = urlunparse(parsed._replace(query=new_query))

        # Basic flags: -sS (silent but show errors), --max-time
        parts = ["curl", "-sS", f"--max-time {int(timeout)}"]

        if insecure_tls:
            parts.append("-k")
        
        # Include headers (-i) is very important for recon to see Server, Cookies, etc.
        if include_headers:
            parts.append("-i")
            
        # Add timing measurement for time-based injection detection
        if is_time_based_injection:
            parts.extend(["-w", '"Duration: %{time_total}s\\n"'])
            
        # Verbose for debugging
        parts.append("-v")

        # 2) Method
        if method.upper() != "GET":
            parts.extend(["-X", method.upper()])

        # 3) Headers
        if headers:
            for k, v in headers.items():
                parts.extend(["-H", shlex.quote(f"{k}: {v}")])

        # 4) Cookies
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            parts.extend(["-H", shlex.quote(f"Cookie: {cookie_str}")])
        
        # AUTOMATED COOKIE MANAGEMENT
        COOKIE_JAR = "/tmp/pentest_cookies.txt"
        # Always read from the shared jar
        parts.extend(["-b", shlex.quote(COOKIE_JAR)])
            
        # Write to jar if this is a login attempt
        # curl only writes cookies when server sends Set-Cookie, so no risk of corruption
        if is_login:
            parts.extend(["-c", shlex.quote(COOKIE_JAR)])

        # 5) Body
        body_cmd = None
        if body_type == "form" and data:
            form_encoded = urlencode(data)
            if not (headers and any(h.lower() == "content-type" for h in headers)):
                parts.extend(["-H", shlex.quote("Content-Type: application/x-www-form-urlencoded")])
            body_cmd = f"-d {shlex.quote(form_encoded)}"
        elif body_type == "json" and data:
            json_str = json.dumps(data)
            if not (headers and any(h.lower() == "content-type" for h in headers)):
                parts.extend(["-H", shlex.quote("Content-Type: application/json")])
            body_cmd = f"--data-binary {shlex.quote(json_str)}"
        elif body_type == "raw" and raw_body is not None:
            body_cmd = f"--data-binary {shlex.quote(raw_body)}"

        if body_cmd:
            parts.append(body_cmd)

        # 6) Final URL
        parts.append(shlex.quote(url))

        cmd = " ".join(parts)

        # Ensure output directory exists (using domain from URL)
        _, domain = parse_target(url)
        outdir = _ensure_outdir(domain)
        # We might want to save distinct files if multiple calls, but for now overwrite or append? 
        # The original tool overwrote "curl_recon.txt". 
        # To avoid conflicts, maybe use a timestamp or a hash? 
        # But for simplicity and keeping with the pattern:
        filename = f"curl_recon_{int(datetime.now().timestamp())}.txt"
        outpath = os.path.join(outdir, filename)

        rc, out = _safe_run_remote(cmd, timeout + 5)

        if rc != 0:
            return f"Curl recon failed (rc={rc}): {out[:8000]}"
        
        # Check if this was a successful login and mark session as established
        if is_login and check_login_success(out):
            mark_session_established()

        # Write result to file
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(out)
        
        cookie_status = f"\nCOOKIES SAVED TO: {COOKIE_JAR}" if is_login else f"\nUSING COOKIES FROM: {COOKIE_JAR}"
        return f"CURL RECON RESULT saved to {outpath}{cookie_status}\nCMD: {cmd}\n\n{out[:8000]}"

    except Exception as e:
        return f"Curl recon error: {e}"

class DirsearchInput(BaseModel):
    target: str = Field(..., description="Target URL (e.g., 'http://example.com' or 'http://192.168.1.1:8080')")
    extensions: Optional[str] = Field(
        default="php,html,js,txt,zip,bak",
        description="File extensions to search for (comma-separated)"
    )
    wordlist: Optional[str] = Field(
        default="/usr/share/wordlists/dirb/common.txt",
        description="Path to wordlist file on Kali Linux"
    )
    threads: int = Field(
        default=20,
        description="Number of threads (1-100)"
    )
    exclude_status: Optional[str] = Field(
        default="404",
        description="Status codes to exclude (comma-separated)"
    )

@tool(args_schema=DirsearchInput)
def dirsearch_tool(
    target: str,
    extensions: str = "php,html,js,txt,zip,bak",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    threads: int = 20,
    exclude_status: str = "404,403"
):
    """
    Directory and file enumeration tool using dirsearch on Kali Linux.
    
    PRIMARY USE: Discover hidden directories, files, and endpoints on web servers.
    
    Parameters:
    - target: Target URL (e.g., 'http://example.com' or 'http://192.168.1.1:8080')
    - extensions: File extensions to search for (default: "php,html,js,txt,zip,bak")
    - wordlist: Path to wordlist file (default: /usr/share/wordlists/dirb/common.txt)
    - threads: Number of threads (default: 20, range: 1-100)
    - exclude_status: Status codes to exclude (default: "404,403")
    
    What Dirsearch Finds:
    - Hidden directories (/admin, /backup, /config, etc.)
    - Sensitive files (config.php, .env, backup.zip, etc.)
    - API endpoints (/api/v1/, /rest/, etc.)
    - Admin panels and login pages
    - Backup files and archives
    - Source code files (.bak, .old, .swp, etc.)
    
    Returns:
    - List of discovered paths with status codes and sizes
    - Results are saved to recon_output/<domain>/dirsearch.txt
    
    Usage:
    - dirsearch_tool(target="http://example.com")  # Basic scan
    - dirsearch_tool(target="http://target.com", extensions="php,asp,aspx", threads=30)  # Custom extensions
    - dirsearch_tool(target="http://target.com", wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")  # Large wordlist
    
    WHEN TO USE:
    - After initial fingerprinting to discover hidden resources
    - To find admin panels, backup files, and sensitive endpoints
    - Before exploitation to map the attack surface
    """
    _, domain = parse_target(target)
    outdir = _ensure_outdir(domain)
    outpath = os.path.join(outdir, "dirsearch.txt")
    
    try:
        # Build dirsearch command
        cmd_parts = [
            "dirsearch",
            "-u", shlex.quote(target),
            "-e", shlex.quote(extensions),
            "-w", shlex.quote(wordlist),
            "-t", str(threads),
            "--exclude-status", shlex.quote(exclude_status),
            "--format=plain",
            "--quiet-mode"
        ]
        cmd = " ".join(cmd_parts)
        
        # Run with extended timeout for large wordlists
        timeout = 180
        rc, out = _safe_run_remote(cmd, timeout)
        
        if rc != 0:
            return f"Dirsearch failed (rc={rc}): {out[:8000]}"
        
        # Save results
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(out)
        
        return f"DIRSEARCH RESULTS saved to {outpath}\\nCMD: {cmd}\\n\\n{out[:8000]}"
        
    except Exception as e:
        return f"Dirsearch error: {e}"

class BruteCredentialsInput(BaseModel):
    target: str = Field(..., description="Target URL (e.g., 'http://example.com/login')")
    username_field: str = Field(..., description="Name of username field in form (e.g., 'username', 'user', 'email')")
    password_field: str = Field(..., description="Name of password field in form (e.g., 'password', 'pass', 'pwd')")
    usernames: Optional[List[str]] = Field(
        default=["admin", "administrator", "root", "user"],
        description="List of usernames to try"
    )
    passwords: Optional[List[str]] = Field(
        default=["admin", "password", "123456", "root"],
        description="List of passwords to try"
    )
    success_string: Optional[str] = Field(
        default=None,
        description="String that indicates successful login (e.g., 'Welcome', 'Dashboard')"
    )
    failure_string: Optional[str] = Field(
        default="Invalid",
        description="String that indicates failed login (e.g., 'Invalid', 'Incorrect', 'Failed')"
    )
    method: Literal["POST", "GET"] = Field(
        default="POST",
        description="HTTP method for login request"
    )
    login_type: Literal["single-step", "multi-step"] = Field(
        default="single-step",
        description="Login flow type: 'single-step' (username+password together) or 'multi-step' (username first, then password)"
    )
    password_url: Optional[str] = Field(
        default=None,
        description="URL for password submission in multi-step login (if different from target)"
    )

@tool(args_schema=BruteCredentialsInput)
def brute_credentials_tool(
    target: str,
    username_field: str,
    password_field: str,
    usernames: List[str] = ["admin", "administrator", "root", "user"],
    passwords: List[str] = ["admin", "password", "123456", "root"],
    success_string: str = None,
    failure_string: str = "Invalid",
    method: str = "POST",
    login_type: str = "single-step",
    password_url: str = None
):
    """
    Brute-force login forms with support for single-step and multi-step flows.
    
    Parameters:
    - target: Login URL
    - username_field, password_field: Form field names
    - usernames, passwords: Lists to try (default: common creds)
    - success_string, failure_string: Response indicators
    - login_type: "single-step" (default) or "multi-step"
    - password_url: Step 2 URL for multi-step (optional)
    
    Single-step: username+password together (most forms)
    Multi-step: username first → password second (Google-style)
    
    Usage:
    - brute_credentials_tool(target="http://target.com/login", username_field="user", password_field="pass")
    - brute_credentials_tool(target="http://target.com/login", username_field="email", password_field="password", login_type="multi-step")
    """
    _, domain = parse_target(target)
    outdir = _ensure_outdir(domain)
    outpath = os.path.join(outdir, "brute_credentials.txt")
    
    successful_creds = []
    results = []
    
    # Cookie jar for multi-step login
    COOKIE_JAR = "/tmp/brute_cookies.txt"
    
    try:
        for username in usernames:
            for password in passwords:
                if login_type == "single-step":
                    # Traditional single-step login: username + password together
                    data = {username_field: username, password_field: password}
                    form_encoded = urlencode(data)
                    
                    cmd_parts = [
                        "curl", "-sS",
                        "-X", method.upper(),
                        "-d", shlex.quote(form_encoded),
                        "-H", shlex.quote("Content-Type: application/x-www-form-urlencoded"),
                        "--max-time", "10",
                        shlex.quote(target)
                    ]
                    cmd = " ".join(cmd_parts)
                    
                    rc, out = _safe_run_remote(cmd, 15)
                    
                elif login_type == "multi-step":
                    # Multi-step login: username first, then password
                    
                    # Step 1: Submit username
                    data_step1 = {username_field: username}
                    form_encoded_step1 = urlencode(data_step1)
                    
                    cmd_step1_parts = [
                        "curl", "-sS",
                        "-X", method.upper(),
                        "-d", shlex.quote(form_encoded_step1),
                        "-H", shlex.quote("Content-Type: application/x-www-form-urlencoded"),
                        "-c", shlex.quote(COOKIE_JAR),  # Save cookies from step 1
                        "--max-time", "10",
                        shlex.quote(target)
                    ]
                    cmd_step1 = " ".join(cmd_step1_parts)
                    
                    rc_step1, out_step1 = _safe_run_remote(cmd_step1, 15)
                    
                    if rc_step1 != 0:
                        results.append(f"[FAILED] {username}:{password} - Step 1 failed")
                        continue
                    
                    # Step 2: Submit password (using cookies from step 1)
                    data_step2 = {password_field: password}
                    form_encoded_step2 = urlencode(data_step2)
                    
                    # Use password_url if provided, otherwise use target
                    step2_url = password_url if password_url else target
                    
                    cmd_step2_parts = [
                        "curl", "-sS",
                        "-X", method.upper(),
                        "-d", shlex.quote(form_encoded_step2),
                        "-H", shlex.quote("Content-Type: application/x-www-form-urlencoded"),
                        "-b", shlex.quote(COOKIE_JAR),  # Load cookies from step 1
                        "--max-time", "10",
                        shlex.quote(step2_url)
                    ]
                    cmd_step2 = " ".join(cmd_step2_parts)
                    
                    rc, out = _safe_run_remote(cmd_step2, 15)
                    cmd = f"STEP1: {cmd_step1}\\nSTEP2: {cmd_step2}"
                
                else:
                    results.append(f"[ERROR] Invalid login_type: {login_type}")
                    continue
                
                # Check for success/failure indicators
                is_success = False
                if success_string and success_string in out:
                    is_success = True
                elif failure_string and failure_string not in out:
                    # If no failure string found, might be success
                    is_success = True
                
                result_line = f"[{'SUCCESS' if is_success else 'FAILED'}] {username}:{password}"
                results.append(result_line)
                
                if is_success:
                    successful_creds.append(f"{username}:{password}")
                    # Mark session as established if we found valid creds
                    mark_session_established()
                
                # Rate limiting: 1 second delay between attempts
                import time
                time.sleep(1)
        
        # Save all results
        output = "\\n".join(results)
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(output)
        
        if successful_creds:
            creds_summary = "\\n".join(successful_creds)
            return f"BRUTE FORCE COMPLETE - FOUND VALID CREDENTIALS:\\n{creds_summary}\\n\\nFull results saved to {outpath}"
        else:
            return f"BRUTE FORCE COMPLETE - No valid credentials found.\\n\\nFull results saved to {outpath}\\n\\n{output[:2000]}"
        
    except Exception as e:
        return f"Brute credentials error: {e}"

def get_all_recon_tools(advance_mode: bool = False):
    """
    Get recon tools. If advance_mode is True, include advanced tools.
    """
    return [whatweb_tool, curl_recon, dirsearch_tool, brute_credentials_tool]

tools_description = """
### whatweb_tool
Web technology fingerprinting tool using WhatWeb on Kali Linux.

PRIMARY USE: Identify web technologies, frameworks, CMS, server software, and potential vulnerabilities.

Parameters:
- target: Target URL (e.g., 'http://example.com' or 'http://192.168.1.1:8080')

What WhatWeb Detects:
- Web servers (Apache, Nginx, IIS, etc.)
- CMS platforms (WordPress, Joomla, Drupal, etc.)
- Programming languages (PHP, Python, Ruby, ASP.NET, etc.)
- JavaScript frameworks (jQuery, React, Angular, Vue.js, etc.)
- Analytics tools (Google Analytics, etc.)
- Security headers and configurations
- Version information for detected technologies
- Cookies and session management details

Returns:
- Detailed fingerprint results including detected technologies, versions, and confidence levels
- Results are saved to recon_output/<domain>/whatweb.txt

Usage:
- whatweb_tool(target="http://example.com")  # Basic fingerprinting
- whatweb_tool(target="http://192.168.1.100:8080")  # Custom port

WHEN TO USE:
- At the beginning of reconnaissance to understand target's technology stack
- Before exploitation to identify potential attack vectors
- To detect outdated software versions with known vulnerabilities

### curl_recon
Advanced reconnaissance tool for HTTP requests and response inspection.

PRIMARY USE: Discover endpoints, forms, headers, cookies, and server behaviors during reconnaissance.

Parameters:
- url: Full URL to scan/inspect
- method: HTTP method (GET/POST/HEAD/OPTIONS/PUT)
- query_params: Query parameters dict
- headers: Custom headers dict
- cookies: Cookies dict
- body_type: "none" | "form" | "json" | "raw"
- data: Data dict (for form/json body)
- raw_body: Raw string (for raw body)
- include_headers: Include response headers (default: True, critical for recon)
- is_login: Set True if this is a login attempt to save cookies
- is_time_based_injection: Set True to measure response time for time-based vulnerability detection (blind SQLi, time-based RCE)

COOKIE MANAGEMENT:
- All requests auto-load cookies from /tmp/pentest_cookies.txt
- Set is_login=True on login POST to save new session cookies
- Subsequent requests will use saved cookies automatically

Returns:
- Response with headers, body, cookie status, and duration (if is_time_based_injection=True)

Usage:
- curl_recon(url="http://target.com/admin", method="GET")  # Discover endpoint
- curl_recon(url="/login", method="POST", body_type="form", data={"user": "admin", "pass": "admin"}, is_login=True)  # Login
- curl_recon(url="/api/data", method="POST", body_type="json", data={"id": 1})  # JSON request
- curl_recon(url="/search?q=test' AND SLEEP(5)--", is_time_based_injection=True)  # Time-based SQLi test

### dirsearch_tool
Directory and file enumeration tool using dirsearch on Kali Linux.

PRIMARY USE: Discover hidden directories, files, and endpoints on web servers.

Parameters:
- target: Target URL (e.g., 'http://example.com' or 'http://192.168.1.1:8080')
- extensions: File extensions to search for (default: "php,html,js,txt,zip,bak")
- wordlist: Path to wordlist file (default: /usr/share/wordlists/dirb/common.txt)
- threads: Number of threads (default: 20, range: 1-100)
- exclude_status: Status codes to exclude (default: "404,403")

What Dirsearch Finds:
- Hidden directories (/admin, /backup, /config, etc.)
- Sensitive files (config.php, .env, backup.zip, etc.)
- API endpoints (/api/v1/, /rest/, etc.)
- Admin panels and login pages
- Backup files and archives
- Source code files (.bak, .old, .swp, etc.)

Returns:
- List of discovered paths with status codes and sizes
- Results are saved to recon_output/<domain>/dirsearch.txt

Usage:
- dirsearch_tool(target="http://example.com")  # Basic scan
- dirsearch_tool(target="http://target.com", extensions="php,asp,aspx", threads=30)  # Custom extensions
- dirsearch_tool(target="http://target.com", wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")  # Large wordlist

WHEN TO USE:
- After initial fingerprinting to discover hidden resources
- To find admin panels, backup files, and sensitive endpoints
- Before exploitation to map the attack surface

### brute_credentials_tool
Credential brute-forcing tool for login forms with support for both single-step and multi-step login flows.

PRIMARY USE: Test common username/password combinations on login forms.

Parameters:
- target: Target login URL (e.g., 'http://example.com/login')
- username_field: Name of username field in form (e.g., 'username', 'user', 'email')
- password_field: Name of password field in form (e.g., 'password', 'pass', 'pwd')
- usernames: List of usernames to try (default: ["admin", "administrator", "root", "user"])
- passwords: List of passwords to try (default: ["admin", "password", "123456", "root"])
- success_string: String indicating successful login (e.g., 'Welcome', 'Dashboard')
- failure_string: String indicating failed login (default: "Invalid")
- method: HTTP method (default: "POST")
- login_type: "single-step" (username+password together) or "multi-step" (username first, then password)
- password_url: URL for password submission in multi-step login (optional, defaults to target)

Login Flow Types:
1. SINGLE-STEP: Traditional login form where username and password are submitted together
   - Example: Most basic login forms
   
2. MULTI-STEP: Modern login flow where username is submitted first, then password on next page
   - Example: Google, Microsoft, some enterprise portals
   - Step 1: Submit username to target URL
   - Step 2: Submit password to password_url (or target if not specified)
   - Cookies from step 1 are automatically carried to step 2

Attack Strategy:
- Tests all username/password combinations
- Detects successful login by response content
- Saves successful credentials for later use
- Respects rate limiting (1 second delay between attempts)
- For multi-step: Automatically manages cookies between steps

Returns:
- List of successful credential pairs
- Results are saved to recon_output/<domain>/brute_credentials.txt

Usage:
SINGLE-STEP:
- brute_credentials_tool(target="http://target.com/login", username_field="user", password_field="pass")
- brute_credentials_tool(target="http://target.com/admin", username_field="username", password_field="password", usernames=["admin"], passwords=["admin123", "password123"])

MULTI-STEP:
- brute_credentials_tool(target="http://target.com/login", username_field="email", password_field="password", login_type="multi-step")
- brute_credentials_tool(target="http://target.com/step1", username_field="username", password_field="pwd", login_type="multi-step", password_url="http://target.com/step2")

WHEN TO USE:
- After discovering login forms with dirsearch or manual recon
- When default credentials might be in use
- As part of initial access attempts

WARNING: Use only on authorized targets. May trigger account lockouts or IDS alerts.
"""