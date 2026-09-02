from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


FAMILY_ATTEMPT_CAP = 4
REQUEST_SHAPE_REPLAN_CAP = 3


@dataclass
class ResponseAnalysis:
    execution_ok: bool
    request_shape_invalid: bool
    same_as_baseline: bool
    status_codes: List[int] = field(default_factory=list)
    redirect_locations: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def _extract_status_codes(result_text: str) -> List[int]:
    codes = []
    for match in re.findall(r"HTTP/[0-9.]+\s+(\d{3})", result_text or "", re.IGNORECASE):
        try:
            codes.append(int(match))
        except ValueError:
            continue
    return codes


def _extract_redirect_locations(result_text: str) -> List[str]:
    return re.findall(r"(?im)^location:\s*([^\r\n]+)", result_text or "")


def _extract_first_url(text: str) -> str:
    match = re.search(r"https?://[^\s'\"`]+", text or "", re.IGNORECASE)
    return match.group(0) if match else ""


def _surface_key(task_instruction: str) -> str:
    url = _extract_first_url(task_instruction)
    if not url:
        normalized = re.sub(r"\s+", " ", task_instruction or "").strip().lower()
        return normalized[:180]
    parsed = urlparse(url)
    method_match = re.search(r"\b(GET|POST|PUT|DELETE|PATCH)\b", task_instruction or "", re.IGNORECASE)
    method = method_match.group(1).upper() if method_match else "GET"
    return f"{method} {parsed.path or '/'}"


def _infer_attempt_family(task_instruction: str, reflection_outcome: Optional[Dict[str, Any]] = None) -> str:
    reflection_family = str((reflection_outcome or {}).get("attempt_family", "")).strip()
    if reflection_family:
        return reflection_family

    text = (task_instruction or "").lower()
    if any(token in text for token in ("double encode", "double-encode", "%25", "url-encode", "url encode", "encoding")):
        return "encoded-payload"
    if any(token in text for token in ("waf", "bypass", "tamper", "obfuscat")):
        return "filter-bypass"
    if any(token in text for token in ("ssrf", "fetch", "callback", "webhook")):
        return "ssrf-fetch"
    if any(token in text for token in ("header", "x-forwarded", "host:")):
        return "header-override"
    if any(token in text for token in ("login", "authenticate", "session", "cookie")):
        return "auth-session"
    if any(token in text for token in ("form body", "application/x-www-form-urlencoded", "/profile", "/update", "/settings")):
        return "form-submission"
    if any(token in text for token in ("union", "select", "sqli", "sql injection", "' or ", "\" or ")):
        return "sqli-probe"
    return "generic-http"


def infer_attempt_family(
    task_instruction: str,
    reflection_outcome: Optional[Dict[str, Any]] = None,
    analyzer_state: Optional[Dict[str, Any]] = None,
) -> str:
    analyzer_family = str((analyzer_state or {}).get("attempt_family", "")).strip()
    if analyzer_family:
        return analyzer_family
    return _infer_attempt_family(task_instruction, reflection_outcome)


def analyze_response(
    *,
    task_instruction: str,
    result_text: str,
    reflection_outcome: Optional[Dict[str, Any]] = None,
) -> ResponseAnalysis:
    result = result_text or ""
    lower_result = result.lower()
    status_codes = _extract_status_codes(result)
    redirects = _extract_redirect_locations(result)
    last_status = status_codes[-1] if status_codes else 0

    execution_ok = bool(
        status_codes
        or re.search(r"\[(?:CMD|curl|CurlHttpRequestTool|IDORTool|whatweb_tool)\]", result)
        or "visited http" in lower_result
    ) and "request_error" not in lower_result

    request_shape_invalid = last_status == 400 or "bad request" in lower_result
    same_as_baseline = bool(
        re.search(r"\bunchanged\b|\bsame endpoint, no progress\b|returned original rows\b", lower_result)
        or ("response body: unchanged" in lower_result)
    )

    notes: List[str] = []
    if request_shape_invalid:
        notes.append("request_shape_invalid")
    if same_as_baseline:
        notes.append("same_as_baseline")
    if "flag{" in lower_result:
        notes.append("flag_observed")
    if "set-cookie" in lower_result:
        notes.append("session_observed")

    return ResponseAnalysis(
        execution_ok=execution_ok,
        request_shape_invalid=request_shape_invalid,
        same_as_baseline=same_as_baseline,
        status_codes=status_codes,
        redirect_locations=redirects,
        notes=notes,
    )


def update_hypothesis_state(
    state: Optional[Dict[str, Dict[str, Any]]],
    *,
    task_instruction: str,
    analysis: ResponseAnalysis,
    task_succeeded: bool,
    reflection_outcome: Optional[Dict[str, Any]] = None,
    analyzer_state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Dict[str, Any]]:
    current = dict(state or {})
    key = _surface_key(task_instruction)
    family = infer_attempt_family(task_instruction, reflection_outcome, analyzer_state)
    item = dict(current.get(key, {}))
    family_stats = dict(item.get("family_stats", {}))
    family_item = dict(family_stats.get(family, {}))

    item["total_attempts"] = int(item.get("total_attempts", 0)) + 1
    item["successful_attempts"] = int(item.get("successful_attempts", 0)) + (1 if task_succeeded else 0)
    item["request_shape_failures"] = int(item.get("request_shape_failures", 0)) + (1 if analysis.request_shape_invalid else 0)
    item["last_family"] = family
    item["last_result_class"] = (
        "success"
        if task_succeeded else
        "request_shape_invalid"
        if analysis.request_shape_invalid else
        "inconclusive"
    )

    family_item["attempts"] = int(family_item.get("attempts", 0)) + 1
    family_item["successes"] = int(family_item.get("successes", 0)) + (1 if task_succeeded else 0)
    family_item["request_shape_failures"] = int(family_item.get("request_shape_failures", 0)) + (1 if analysis.request_shape_invalid else 0)
    family_item["last_result_class"] = item["last_result_class"]

    if task_succeeded:
        family_item["blocked"] = False
        family_item["block_reason"] = ""
    elif analysis.request_shape_invalid and family_item["request_shape_failures"] >= REQUEST_SHAPE_REPLAN_CAP:
        family_item["blocked"] = True
        family_item["block_reason"] = f"Repeated malformed attempts in family {family}."
    else:
        family_item["blocked"] = bool(family_item.get("blocked", False))
        family_item["block_reason"] = str(family_item.get("block_reason", "") or "")

    family_stats[family] = family_item
    item["family_stats"] = family_stats
    current[key] = item
    return current


def summarize_hypothesis_state(
    state: Optional[Dict[str, Dict[str, Any]]],
    *,
    task_instruction: str,
) -> str:
    current = state or {}
    key = _surface_key(task_instruction)
    item = current.get(key)
    if not item:
        return "hypothesis_state=none"

    family = str(item.get("last_family", "") or "unknown")
    family_item = ((item.get("family_stats") or {}).get(family) or {})
    return (
        f"hypothesis_surface={key}\n"
        f"hypothesis_total_attempts={int(item.get('total_attempts', 0))}\n"
        f"hypothesis_successful_attempts={int(item.get('successful_attempts', 0))}\n"
        f"hypothesis_request_shape_failures={int(item.get('request_shape_failures', 0))}\n"
        f"hypothesis_last_family={family}\n"
        f"hypothesis_last_result_class={item.get('last_result_class', '')}\n"
        f"attempt_family_attempts={int(family_item.get('attempts', 0))}\n"
        f"attempt_family_successes={int(family_item.get('successes', 0))}\n"
        f"attempt_family_request_shape_failures={int(family_item.get('request_shape_failures', 0))}\n"
        f"attempt_family_blocked={str(bool(family_item.get('blocked', False))).lower()}\n"
        f"attempt_family_block_reason={family_item.get('block_reason', '') or 'none'}\n"
        f"attempt_family_retry_rule=retry only with a new technical reason, not cosmetic variation"
    )


def should_force_replan(
    state: Optional[Dict[str, Dict[str, Any]]],
    *,
    task_instruction: str,
    analysis: ResponseAnalysis,
    reflection_outcome: Optional[Dict[str, Any]] = None,
    analyzer_state: Optional[Dict[str, Any]] = None,
) -> bool:
    current = state or {}
    key = _surface_key(task_instruction)
    item = current.get(key) or {}
    family = infer_attempt_family(task_instruction, reflection_outcome, analyzer_state)
    family_item = ((item.get("family_stats") or {}).get(family) or {})

    if analysis.request_shape_invalid and int(family_item.get("request_shape_failures", 0)) >= REQUEST_SHAPE_REPLAN_CAP:
        return True

    if bool(family_item.get("blocked", False)):
        return True

    if int(family_item.get("attempts", 0)) >= FAMILY_ATTEMPT_CAP and int(family_item.get("successes", 0)) == 0:
        return True

    return False
