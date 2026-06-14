import json
import re
from typing import Any, Dict, Optional

from models.llm import llm


MAX_REFLECTIONS = 3


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
	if not text:
		return None
	# Try direct parse first
	try:
		obj = json.loads(text)
		if isinstance(obj, dict):
			return obj
	except Exception:
		pass

	# Fallback: extract first JSON object
	m = re.search(r"\{[\s\S]*\}", text)
	if not m:
		return None
	try:
		obj = json.loads(m.group(0))
		if isinstance(obj, dict):
			return obj
	except Exception:
		return None
	return None


def _contains_flag_token(text: str) -> bool:
	"""Return True only for real flag token shapes like flag{...}.

	We intentionally avoid treating the bare word "flag" as success to reduce false positives.
	"""
	if not text:
		return False
	# Allow typical CTF tokens and avoid runaway matches
	return re.search(r"\bflag\{[^\r\n\}]{1,200}\}", text, re.IGNORECASE) is not None


async def intra_reflection(
	*,
	recon_analyzer_output: str,
	exploit_analyzer_output: str,
	tool_runtime_result: str,
	original_task: str,
	current_query: str,
	remaining_reflections: int,
) -> Dict[str, Any]:
	"""
	Intra reflection controller.

	Inputs (per spec):
	- Recon analyzer output
	- Exploit analyzer output
	- Tool / runtime result
	- Original task
	- Remaining reflection count (max 3)

	Output example:
	{
	  "decision": "RETRY"|"STOP"|"SUCCESS",
	  "reason": "...",
	  "next_query": "...",
	  "remaining_reflections": 2
	}
	"""
	remaining = max(0, min(int(remaining_reflections), MAX_REFLECTIONS))

	# SUCCESS override: if a real flag token is present in the observed runtime result, succeed immediately.
	if _contains_flag_token(tool_runtime_result):
		return {
			"decision": "SUCCESS",
			"reason": "Flag token detected in runtime result (flag{...}).",
			"next_query": "",
			"remaining_reflections": remaining,
		}

	prompt = f"""
You are an INTRA-REFLECTION controller.

You MUST operate independently: do NOT rely on external if/else decisions from other components.
Your job is:
1) Decide whether the NEXT_TASK (Original task) has been completed successfully based on the actual runtime result.
2) If NOT completed and budget remains, regenerate a corrected query that better achieves the NEXT_TASK.

SUCCESS:
- Only output SUCCESS when the runtime result contains explicit, concrete evidence that the NEXT_TASK objective is achieved.
- Do NOT infer success from guesses or assumptions.

INPUTS:
1) Next task (planner task / objective):
{original_task}

2) Current query (what was executed):
{current_query}

3) Tool / runtime result (observed responses, stdout/stderr, status):
{tool_runtime_result}

4) Optional context (may be noisy; use only if helpful):
- Recon analyzer output:
{recon_analyzer_output}

- Exploit analyzer output:
{exploit_analyzer_output}

5) Remaining reflection count (max {MAX_REFLECTIONS}):
{remaining}

PROCESS (MUST FOLLOW):
A) Determine whether NEXT_TASK is completed. If yes -> decision=SUCCESS.
B) If not completed:
	- If remaining==0 -> decision=STOP.
	- Else -> decision=RETRY and produce next_query.

NEXT_QUERY RULES (if RETRY):
- Keep the same target scope (same base URL/host/port) as the NEXT_TASK/current query.
- Keep the same attack class and intent as the NEXT_TASK (do NOT open a new vulnerability class).
- Make minimal corrective changes to the query based on observed evidence.
- If the NEXT_TASK is bruteforce/credential guessing: use the dedicated brute_credentials_tool (if available) and DO NOT generate a curl spam loop.

OUTPUT (STRICT JSON ONLY):
Return ONLY one JSON object with EXACTLY these fields:
{{
  "decision": "RETRY" or "STOP" or "SUCCESS",
  "reason": "one short sentence",
  "next_query": "" (empty if decision != RETRY),
  "remaining_reflections": <int>
}}

RULES FOR remaining_reflections:
- If decision == RETRY: decrement by 1.
- Else keep the same value.
"""

	response = await llm.ainvoke(prompt)
	response_text = response.content if hasattr(response, "content") else str(response)
	obj = _extract_json_object(response_text)

	if not obj:
		return {
			"decision": "STOP",
			"reason": "Reflection parse failed; stopping to avoid unsafe/unbounded retries.",
			"next_query": "",
			"remaining_reflections": remaining,
		}

	decision = str(obj.get("decision", "STOP")).strip().upper()
	if decision not in {"RETRY", "STOP", "SUCCESS"}:
		decision = "STOP"

	next_query = str(obj.get("next_query", "") or "")
	reason = str(obj.get("reason", "") or "").strip()[:400]
	new_remaining = obj.get("remaining_reflections", remaining)
	try:
		new_remaining = int(new_remaining)
	except Exception:
		new_remaining = remaining

	# Enforce remaining-reflections contract
	if decision == "RETRY":
		if remaining <= 0:
			return {
				"decision": "STOP",
				"reason": "No reflection budget left for retry.",
				"next_query": "",
				"remaining_reflections": 0,
			}
		enforced_remaining = max(0, remaining - 1)
		# Only accept model's remaining if it matches the contract
		new_remaining = enforced_remaining
		if not next_query.strip() or next_query.strip() == current_query.strip():
			return {
				"decision": "STOP",
				"reason": "Retry requested but next_query missing/unchanged; stopping.",
				"next_query": "",
				"remaining_reflections": remaining,
			}
	else:
		new_remaining = remaining
		next_query = ""

	return {
		"decision": decision,
		"reason": reason or "",
		"next_query": next_query,
		"remaining_reflections": max(0, min(new_remaining, MAX_REFLECTIONS)),
	}

