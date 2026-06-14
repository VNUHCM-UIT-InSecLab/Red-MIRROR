"""
Tool descriptions for Exploiter and Collector agents.
These strings are used in prompts to inform the LLM about available tools.
"""

EXPLOITER_TOOLS = """
AVAILABLE TOOLS:

GoToWebsite: Navigate to a URL using Playwright browser automation.
ClickElement: Click on an element identified by natural language description (LLM-powered XPath generation).
WriteIntoElement: Fill text into an input field identified by natural language description.
FindElement: Find an element's XPath using natural language description.
CurlHttpRequestTool: Send HTTP requests with full control (method, headers, cookies, body). Supports GET/POST/PUT/DELETE, form-urlencoded, JSON, raw bodies. Returns full response including headers. Set is_time_based_injection=True to measure response time for blind vulnerabilities (SQLi, RCE) - outputs "Duration: X.XXXs" for time-based detection. Use for single exploitation attempts (1-5 requests max).
JWTTool: JWT manipulation with 2 modes: (1) decode - extract header and payload from token without verification, (2) encode - create JWT with custom algorithm (HS256/HS384/HS512/RS256/none), secret, header, and payload. In encode mode, pass target_url to save the token immediately into the shared remote cookie jar (/tmp/pentest_cookies.txt on Kali) for that host, replacing the existing auth cookie entry (auto-detects cookie name from jar: token/session/jwt/auth/access_token; defaults to session). If target_url is omitted, JWTTool will try LAST_TARGET_HOST from prior HTTP tools; otherwise cookie jar is not updated.
UploadFileTool: Upload files to endpoints. Supports custom filenames and content types for bypass testing.
IDORTool: Standalone IDOR fuzzing tool. Tests ONE suspected IDOR attack surface at a time by fuzzing a parameter with integer values in a range around the current user ID. Supports fuzzing in headers, query params, or body. Returns JSON with baseline comparison, distinct behaviors clustering, and IDOR confirmation. Use when you have a confirmed AXIS (parameter controlling access) and need to test for unauthorized access across multiple IDs.
SmartXSSTool: Intelligent context-aware XSS fuzzer with guided reinforcement feedback loop. Uses LLM to analyze reflection context, classify injection points, and strategically mutate payloads to bypass filters. Automatically tests multiple parameters (max 50 attempts) and continues until flag{} pattern found in response. Auto-detects wrong HTTP method after 8 consecutive non-reflected attempts and suggests switching GET↔POST. Returns detailed context summary to avoid repeating failed patterns.
SmartSQLiTool: Forensic SQL Injection tool. Fully Agent-driven detection. NO hardcoded tactics, NO predefined modes. Pure signal-driven learning: Generator → Executor → Analyzer → Loop. The agent observes SQL behavior through response signals, generates payload PAIRS to create differential behavior, and decides when to stop. Specify goal in plain English (e.g., "Extract FLAG{}", "Bypass login"). Returns extracted artifact if successful.
SmartCodeInjectionTool: Forensic Code Injection tool. Tests for OS Command Injection (Linux) and Server-Side Template Injection (SSTI). Agent-driven detection with automatic payload generation and result analysis. Requires 'attack_type' ("OS_Command_Linux" or "SSTI") and 'baseline' payload to establish reference behavior.
CVEResearchTool: Research CVE vulnerabilities for specific technology versions. Features: Search NVD database for CVEs, Auto-map technology version to known vulnerabilities, Fetch PoC code from GitHub if available.
CmdExecTool: Execute shell commands on Kali Linux for pentesting tasks.
"""


COLLECTOR_TOOLS = """
whatweb_tool: Lightweight web technology fingerprinting. Identifies web server, CMS, frameworks, and versions. Essential first step for reconnaissance.
curl_recon: Advanced HTTP request tool for reconnaissance. Supports GET/POST/PUT/DELETE, custom headers, cookies, query parameters, form-urlencoded and JSON bodies. Automatically manages cookie jar for session persistence. Use include_headers=True to see server headers and Set-Cookie. Set is_login=True on successful login to save session cookies. Set is_time_based_injection=True to measure response time for time-based vulnerability detection (blind SQLi, time-based RCE).
"""
