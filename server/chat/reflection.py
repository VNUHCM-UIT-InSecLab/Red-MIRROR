import json
import re
import ast
import base64
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from models.llm import llm


MAX_REFLECTIONS = 1
_DECISIONS = {"RETRY", "PIVOT", "STOP", "SUCCESS"}
_FAILURE_CLASSES = {
    "retryable_local_error",
    "valid_attempt_no_signal",
    "partial_positive_signal",
    "known_form_fields_not_preserved",
    "direct_localhost_access_blocked",
    "wrong_artifact_class",
    "success",
}
_JUSTIFICATION_WEAK_PATTERNS = (
    "try again",
    "retry",
    "maybe it works",
    "another payload",
    "different payload",
    "adjust payload",
    "minor tweak",
)


def _extract_urls(text: str) -> list[str]:
    return re.findall(r'https?://[^\s\'"]+', text or "", re.IGNORECASE)


def _infer_attempt_family(text: str) -> str:
    source = (text or "").lower()
    if any(token in source for token in ("double encode", "double-encode", "%25", "url-encode", "url encode", "encoding")):
        return "encoded-payload"
    if any(token in source for token in ("waf", "bypass", "tamper", "obfuscat")):
        return "filter-bypass"
    if any(token in source for token in ("ssrf", "fetch", "callback", "webhook")):
        return "ssrf-fetch"
    if any(token in source for token in ("header", "x-forwarded", "x-real-ip", "host:")):
        return "header-override"
    if any(token in source for token in ("login", "authenticate", "session", "cookie")):
        return "auth-session"
    if any(token in source for token in ("form body", "application/x-www-form-urlencoded", "/profile", "/update", "/settings")):
        return "form-submission"
    if any(token in source for token in ("union", "select", "sqli", "sql injection", "' or ", "\" or ")):
        return "sqli-probe"
    if any(token in source for token in ("idor", "user_id", "account_id", "order_id")):
        return "idor-probe"
    return "generic-http"


def _is_meaningful_retry_justification(text: str) -> bool:
    reason = " ".join((text or "").strip().lower().split())
    if len(reason) < 24:
        return False
    if all(token not in reason for token in ("because", "due to", "based on", "since", "observed", "server", "parse", "decode", "filter", "context", "encoding", "header", "cookie", "field", "shape", "sink", "quote")):
        return False
    if any(pattern == reason or reason.startswith(pattern + " ") for pattern in _JUSTIFICATION_WEAK_PATTERNS):
        return False
    return True


def _normalize_same_app_ssrf_loopback_ports(text: str) -> str:
    raw = text or ""
    lowered = raw.lower()
    if "validation_endpoints" in lowered or "idortool" in lowered:
        return raw
    if not any(token in lowered for token in ("ssrf", "profile_picture_url", "fetch", "callback", "webhook", "url=")):
        return raw
    urls = _extract_urls(raw)
    if len(urls) < 2:
        return raw
    try:
        target = urlparse(urls[0])
    except Exception:
        return raw
    if not target.port:
        return raw
    normalized = raw
    for candidate in urls[1:]:
        try:
            parsed = urlparse(candidate)
        except Exception:
            continue
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            continue
        if parsed.port != target.port:
            continue
        replacement = f"{parsed.scheme or 'http'}://127.0.0.1{parsed.path or '/'}"
        if parsed.query:
            replacement += f"?{parsed.query}"
        normalized = normalized.replace(candidate, replacement)
    return normalized


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

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
    if not text:
        return False
    return re.search(r"\bflag\{[^\r\n\}]{1,200}\}", text, re.IGNORECASE) is not None


def _looks_malformed_or_local_error(text: str) -> bool:
    return bool(re.search(
        r"traceback|exception|invalid\s+(url|json|argument|payload)|malformed|parse error|syntax error|missing required|tool error|command not found|usage:",
        text or "",
        re.IGNORECASE,
    ))


def _has_http_error_status(text: str) -> bool:
    return bool(re.search(r"http/[0-9.]+\s+[45]\d\d", text or "", re.IGNORECASE))


def _has_hard_client_error(text: str) -> bool:
    return bool(re.search(r"http/[0-9.]+\s+400\b|bad request", text or "", re.IGNORECASE))


def _is_localhost_only_direct_access_blocked(original_task: str, current_query: str, tool_runtime_result: str) -> bool:
    combined = "\n".join(filter(None, [original_task, current_query, tool_runtime_result]))
    targets_local_only = bool(re.search(
        r"reset_password|localhost[-\s]restricted|only accessible from localhost|127\.0\.0\.1|localhost",
        combined,
        re.IGNORECASE,
    ))
    direct_header_bypass = bool(re.search(
        r"headers?\s*=\s*\{.*(?:Host|X-Forwarded-For|X-Real-IP|X-Forwarded-Host|X-Client-IP)",
        current_query or "",
        re.IGNORECASE,
    ))
    blocked = bool(re.search(r"http/[0-9.]+\s+40[13]|forbidden|unauthorized", tool_runtime_result or "", re.IGNORECASE))
    return targets_local_only and blocked and (direct_header_bypass or "reset_password" in (current_query or ""))


def _looks_partial_positive_signal(text: str) -> bool:
    return bool(re.search(
        r"sleep\s*\d+|delayed?\s+response|time-?based|sql syntax|stack trace|reflected|permission denied|403 forbidden|401 unauthorized|500 internal",
        text or "",
        re.IGNORECASE,
    ))


def _looks_valid_attempt_no_signal(text: str) -> bool:
    return bool(re.search(
        r"\[(?:curl|curlhttprequesttool|idortool|smartsqlitool|playwright|cmdexec|whatweb_tool)\]|http/[0-9.]+\s+[1-5]\d\d|status\s*[:=]\s*[1-5]\d\d|response",
        text or "",
        re.IGNORECASE,
    ))


def _contains_non_retryable_non_jwt(text: str) -> bool:
    return "NON_RETRYABLE_NON_JWT" in (text or "")


def _extract_sent_fields_from_query(query: str) -> list[str]:
    text = query or ""
    for field_name in ("form_body", "json_body"):
        m = re.search(rf"{field_name}\s*=\s*(\{{[\s\S]*?\}})", text)
        if not m:
            continue
        try:
            obj = ast.literal_eval(m.group(1))
        except Exception:
            continue
        if isinstance(obj, dict):
            return [str(k) for k in obj.keys()]
    return []


def _extract_known_form_fields(text: str) -> list[str]:
    source = text or ""
    fields: list[str] = []
    fields.extend(name.strip() for name in re.findall(r'name=["\']([^"\']+)["\']', source, re.IGNORECASE))
    fields.extend(name.strip() for name in re.findall(r"-\s*`([A-Za-z0-9_.-]+)`\s*:", source))

    seen = set()
    normalized = []
    for field in fields:
        lower = field.lower()
        if lower in {"submit", "csrf", "_csrf_token"}:
            continue
        if lower not in seen:
            seen.add(lower)
            normalized.append(field)
    return normalized


def _infer_known_form_shape_issue(current_query: str, combined_text: str) -> Optional[Dict[str, Any]]:
    sent_fields = _extract_sent_fields_from_query(current_query)
    known_fields = _extract_known_form_fields(combined_text)
    if not sent_fields or not known_fields:
        return None

    sent_lower = {field.lower() for field in sent_fields}
    missing_fields = [field for field in known_fields if field.lower() not in sent_lower]
    is_form_like_query = bool(re.search(r"/(?:profile|edit|update|settings|account)\b|form_body\s*=", current_query or "", re.IGNORECASE))
    looks_validation_failure = bool(re.search(r"http/[0-9.]+\s+400|bad request|required|missing|validation", combined_text or "", re.IGNORECASE))

    if is_form_like_query and looks_validation_failure and missing_fields:
        return {
            "sent_fields": sent_fields,
            "known_fields": known_fields,
            "missing_fields": missing_fields,
        }
    return None


def _build_preserve_form_retry_query(current_query: str, shape_issue: Dict[str, Any]) -> str:
    known_fields = ", ".join(shape_issue.get("known_fields", []))
    missing_fields = ", ".join(shape_issue.get("missing_fields", []))
    return (
        f"{current_query.strip()}\n\n"
        "Correction: preserve the known form shape from earlier evidence. "
        f"Known sibling fields: {known_fields}. "
        f"Previously omitted fields: {missing_fields}. "
        "Retry the same attack class while preserving all known sibling fields and mutating only the target field under test. "
        "Do not switch content type unless the observed form was actually JSON."
    )


def _task_mentions_flag_objective(task: str) -> bool:
    task_lower = (task or "").lower()
    return "flag{" in task_lower or "retrieve the flag" in task_lower or "read the flag" in task_lower or "get the flag" in task_lower


def _extract_expected_login_identity(task: str) -> Optional[str]:
    text = task or ""
    form_match = re.search(r"form body\s+[^,\n]*username=([A-Za-z0-9_.@-]+)", text, re.IGNORECASE)
    if form_match:
        return form_match.group(1).strip()
    patterns = [
        r"login as\s+([A-Za-z0-9_.@-]+)",
        r"authenticate as\s+([A-Za-z0-9_.@-]+)",
        r"username['\"=:\s]+([A-Za-z0-9_.@-]+)",
    ]
    stopwords = {"the", "a", "an", "newly", "registered", "created", "user", "admin", "account"}
    for pattern in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            candidate = m.group(1).strip().rstrip(".,;:!?)\"]}'")
            if candidate.lower() in stopwords:
                continue
            return candidate
    return None


def _runtime_confirms_identity(runtime_result: str, expected_identity: Optional[str]) -> bool:
    if not expected_identity:
        return False
    runtime = runtime_result or ""
    identity = expected_identity.strip()
    identity_re = re.escape(identity)

    if re.search(rf"session established as {identity_re}\b|logged in as {identity_re}\b|welcome[,\s]+{identity_re}\b", runtime, re.IGNORECASE):
        return True

    cookie_match = re.search(r"(?im)^set-cookie:\s*session=([^;\r\n]+)", runtime)
    if not cookie_match:
        return False
    cookie_value = cookie_match.group(1).strip()
    first_segment = cookie_value.split(".", 1)[0].strip()
    if not first_segment:
        return False
    try:
        padding = (-len(first_segment)) % 4
        decoded = base64.urlsafe_b64decode(first_segment + ("=" * padding)).decode("utf-8")
        obj = json.loads(decoded)
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    for key in ("username", "user", "login", "email", "sub"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower() == identity.lower()
    return False


def _runtime_explicitly_negates_flag_success(runtime_result: str) -> bool:
    return bool(re.search(
        r"flag (?:artifact )?not present|flag endpoint not found|though the flag .* not present|no flag found",
        runtime_result or "",
        re.IGNORECASE,
    ))


def _runtime_explicitly_negates_identity(runtime_result: str, expected_identity: Optional[str]) -> bool:
    if not expected_identity:
        return False
    runtime = runtime_result or ""
    identity = re.escape(expected_identity)
    if re.search(
        rf"expected {identity}.*got [A-Za-z0-9_.@-]+|not {identity}\b|references [A-Za-z0-9_.@-]+, not {identity}\b",
        runtime,
        re.IGNORECASE,
    ):
        return True
    cookie_match = re.search(r"(?im)^set-cookie:\s*session=([^;\r\n]+)", runtime)
    if not cookie_match:
        return False
    cookie_value = cookie_match.group(1).strip()
    first_segment = cookie_value.split(".", 1)[0].strip()
    if not first_segment:
        return False
    try:
        padding = (-len(first_segment)) % 4
        decoded = base64.urlsafe_b64decode(first_segment + ("=" * padding)).decode("utf-8")
        obj = json.loads(decoded)
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    for key in ("username", "user", "login", "email", "sub"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower() != expected_identity.strip().lower()
    return False


def _objective_is_explicitly_satisfied(original_task: str, tool_runtime_result: str) -> bool:
    if _has_http_error_status(tool_runtime_result):
        return False

    if _task_mentions_flag_objective(original_task):
        return _contains_flag_token(tool_runtime_result) and not _runtime_explicitly_negates_flag_success(tool_runtime_result)

    expected_identity = _extract_expected_login_identity(original_task)
    if expected_identity:
        return _runtime_confirms_identity(tool_runtime_result, expected_identity) and not _runtime_explicitly_negates_identity(tool_runtime_result, expected_identity)

    if re.search(r"reset (?:the )?admin password|reset_password|password reset", original_task or "", re.IGNORECASE):
        return bool(re.search(r"password reset success|reset successful|password changed", tool_runtime_result or "", re.IGNORECASE))

    return False


async def _ask_reflection_model(*, original_task: str, current_query: str, tool_runtime_result: str,
                                recon_analyzer_output: str, exploit_analyzer_output: str,
                                remaining: int, structured_evidence: str = "") -> Optional[Dict[str, Any]]:
    prompt = f"""
You are an INTRA-REFLECTION controller.
Classify the outcome of the latest attempt for the planner task.

Task objective:
{original_task}

Current query:
{current_query}

Runtime result:
{tool_runtime_result}

Recon analyzer output:
{recon_analyzer_output}

Exploit analyzer output:
{exploit_analyzer_output}

Structured evidence:
{structured_evidence}

Remaining reflections: {remaining}

Decision rules:
- SUCCESS only if the task objective is explicitly achieved in the runtime result.
- RETRY only when the same hypothesis still makes sense and the next attempt has a concrete technical reason to work better than the previous one.
- Use retryable_local_error for malformed request/tool usage. Use partial_positive_signal only when the runtime result provides concrete technical evidence for a narrowly targeted correction, not for generic hope.
- For form-like POST/update/profile/settings requests with HTTP 400 / Bad Request, prioritize form shape before encoding or payload theory. If known sibling fields were omitted, preserve the full known shape on retry. If exact shape is unknown, inspect first.
- If a localhost-only/internal endpoint returns 401/403 to direct access or simple header spoofing, do not call that SUCCESS and do not keep retrying header swaps. Treat that vector as blocked and PIVOT to a different delivery path.
- If the runtime result contains NON_RETRYABLE_NON_JWT or says the artifact is not a confirmed JWT candidate, do NOT choose RETRY. That is a wrong-artifact-class outcome and must PIVOT or STOP.
- PIVOT when the current hypothesis is exhausted, contradicted, or only supported by cosmetic variations of the same attempt family.
- STOP only when there is no remaining budget or you cannot propose a concrete technically justified next query.
- Distinguish "same hypothesis but wrong format" from "valid attempt but no signal".

Output STRICT JSON ONLY with exactly these fields:
{{
  "decision": "RETRY" | "PIVOT" | "STOP" | "SUCCESS",
  "failure_class": "retryable_local_error" | "valid_attempt_no_signal" | "partial_positive_signal" | "known_form_fields_not_preserved" | "direct_localhost_access_blocked" | "wrong_artifact_class" | "success",
  "attempt_family": "short family label for the technical attempt class",
  "retry_justification": "for RETRY only: why the next attempt is technically different and justified",
  "reason": "short sentence",
  "next_query": "",
  "remaining_reflections": {remaining}
}}
"""
    response = await llm.ainvoke(prompt)
    response_text = response.content if hasattr(response, "content") else str(response)
    return _extract_json_object(response_text)


async def _legacy_intra_reflection(
    *,
    recon_analyzer_output: str,
    exploit_analyzer_output: str,
    tool_runtime_result: str,
    original_task: str,
    current_query: str,
    remaining_reflections: int,
) -> Dict[str, Any]:
    remaining = max(0, min(int(remaining_reflections), MAX_REFLECTIONS))
    combined_text = "\n".join(filter(None, [tool_runtime_result, recon_analyzer_output, exploit_analyzer_output]))
    form_shape_issue = _infer_known_form_shape_issue(current_query, combined_text)
    localhost_blocked_issue = _is_localhost_only_direct_access_blocked(original_task, current_query, tool_runtime_result)
    structured_evidence = ""
    if form_shape_issue:
        structured_evidence = (
            f"sent_fields={form_shape_issue['sent_fields']}; "
            f"known_form_fields={form_shape_issue['known_fields']}; "
            f"missing_known_fields={form_shape_issue['missing_fields']}"
        )
    if localhost_blocked_issue:
        structured_evidence = (structured_evidence + "\n" if structured_evidence else "") + (
            "direct_localhost_access_blocked=true; "
            "observation=localhost-only endpoint returned 401/403 to direct/header-spoofed request"
        )

    if _objective_is_explicitly_satisfied(original_task, tool_runtime_result) or _contains_flag_token(tool_runtime_result):
        return {
            "decision": "SUCCESS",
            "failure_class": "success",
            "attempt_family": _infer_attempt_family(current_query or original_task),
            "retry_justification": "",
            "reason": "Objective evidence detected in runtime result.",
            "next_query": "",
            "remaining_reflections": remaining,
        }

    if remaining <= 0:
        return {
            "decision": "STOP",
            "failure_class": "valid_attempt_no_signal",
            "attempt_family": _infer_attempt_family(current_query or original_task),
            "retry_justification": "",
            "reason": "No reflection budget left.",
            "next_query": "",
            "remaining_reflections": 0,
        }

    heuristic_failure_class = "valid_attempt_no_signal"
    heuristic_decision = "PIVOT"
    if _contains_non_retryable_non_jwt(combined_text):
        heuristic_failure_class = "wrong_artifact_class"
        heuristic_decision = "PIVOT"
    elif localhost_blocked_issue:
        heuristic_failure_class = "direct_localhost_access_blocked"
        heuristic_decision = "PIVOT"
    elif form_shape_issue:
        heuristic_failure_class = "known_form_fields_not_preserved"
        heuristic_decision = "RETRY"
    elif _looks_malformed_or_local_error(combined_text):
        heuristic_failure_class = "retryable_local_error"
        heuristic_decision = "RETRY"
    elif _looks_partial_positive_signal(combined_text):
        heuristic_failure_class = "partial_positive_signal"
        heuristic_decision = "RETRY"
    elif not _looks_valid_attempt_no_signal(combined_text):
        heuristic_decision = "STOP"

    obj = await _ask_reflection_model(
        original_task=original_task,
        current_query=current_query,
        tool_runtime_result=tool_runtime_result,
        recon_analyzer_output=recon_analyzer_output,
        exploit_analyzer_output=exploit_analyzer_output,
        remaining=remaining,
        structured_evidence=structured_evidence,
    )

    if not obj:
        decision = heuristic_decision
        failure_class = heuristic_failure_class
        attempt_family = _infer_attempt_family(current_query or original_task)
        retry_justification = ""
        next_query = ""
        reason = "Reflection parse failed; using bounded fallback policy."
    else:
        decision = str(obj.get("decision", heuristic_decision)).strip().upper()
        failure_class = str(obj.get("failure_class", heuristic_failure_class)).strip()
        attempt_family = str(obj.get("attempt_family", "") or "").strip() or _infer_attempt_family(current_query or original_task)
        retry_justification = str(obj.get("retry_justification", "") or "").strip()[:500]
        next_query = str(obj.get("next_query", "") or "")
        reason = str(obj.get("reason", "") or "").strip()[:400]
        if decision not in _DECISIONS:
            decision = heuristic_decision
        if failure_class not in _FAILURE_CLASSES:
            failure_class = heuristic_failure_class

    if decision == "SUCCESS":
        if localhost_blocked_issue:
            return {
                "decision": "PIVOT",
                "failure_class": "direct_localhost_access_blocked",
                "attempt_family": attempt_family,
                "retry_justification": "",
                "reason": "Model claimed SUCCESS but the localhost-only endpoint still returned 401/403 to the direct access vector.",
                "next_query": "",
                "remaining_reflections": remaining,
            }
        if _has_http_error_status(tool_runtime_result):
            return {
                "decision": "RETRY" if form_shape_issue else ("PIVOT" if (_has_hard_client_error(tool_runtime_result) or heuristic_decision == "PIVOT") else "STOP"),
                "failure_class": "known_form_fields_not_preserved" if form_shape_issue else heuristic_failure_class,
                "attempt_family": "form-submission" if form_shape_issue else attempt_family,
                "retry_justification": "Retry only to preserve the full observed form shape because the current request returned an HTTP error.",
                "reason": "Model claimed SUCCESS but runtime result still contains an HTTP error status.",
                "next_query": _build_preserve_form_retry_query(current_query, form_shape_issue) if form_shape_issue else "",
                "remaining_reflections": max(0, remaining - 1) if form_shape_issue else remaining,
            }
        if not _objective_is_explicitly_satisfied(original_task, tool_runtime_result) and not _contains_flag_token(tool_runtime_result):
            return {
                "decision": "PIVOT" if heuristic_decision == "PIVOT" else "STOP",
                "failure_class": heuristic_failure_class if heuristic_failure_class != "success" else "valid_attempt_no_signal",
                "attempt_family": attempt_family,
                "retry_justification": "",
                "reason": "Model claimed SUCCESS but runtime result does not explicitly satisfy the task objective.",
                "next_query": "",
                "remaining_reflections": remaining,
            }
        failure_class = "success"
        next_query = ""
        return {
            "decision": decision,
            "failure_class": failure_class,
            "attempt_family": attempt_family,
            "retry_justification": "",
            "reason": reason or "Objective satisfied.",
            "next_query": next_query,
            "remaining_reflections": remaining,
        }

    if decision == "RETRY":
        if _contains_non_retryable_non_jwt(combined_text) or failure_class == "wrong_artifact_class":
            return {
                "decision": "PIVOT",
                "failure_class": "wrong_artifact_class",
                "attempt_family": attempt_family,
                "retry_justification": "",
                "reason": reason or "Artifact is not a confirmed JWT candidate; pivot instead of retrying JWTTool.",
                "next_query": "",
                "remaining_reflections": remaining,
            }
        if localhost_blocked_issue:
            return {
                "decision": "PIVOT",
                "failure_class": "direct_localhost_access_blocked",
                "attempt_family": "header-override",
                "retry_justification": "",
                "reason": reason or "Direct access to a localhost-only endpoint is blocked; pivot to a different delivery path instead of retrying header spoofing.",
                "next_query": "",
                "remaining_reflections": remaining,
            }
        if form_shape_issue:
            return {
                "decision": "RETRY",
                "failure_class": "known_form_fields_not_preserved",
                "attempt_family": "form-submission",
                "retry_justification": "Retry is justified because the last attempt omitted known sibling fields; the next attempt preserves the full observed form shape while changing only the target field.",
                "reason": reason or "Known form fields were observed earlier but the latest request omitted sibling fields.",
                "next_query": _build_preserve_form_retry_query(current_query, form_shape_issue),
                "remaining_reflections": max(0, remaining - 1),
            }
        if _has_hard_client_error(tool_runtime_result) and remaining <= 1:
            return {
                "decision": "PIVOT",
                "failure_class": "valid_attempt_no_signal",
                "attempt_family": attempt_family,
                "retry_justification": "",
                "reason": reason or "Repeated 400-level client error with no progress; pivot instead of retrying the same request class.",
                "next_query": "",
                "remaining_reflections": remaining,
            }
        if failure_class not in {"retryable_local_error", "partial_positive_signal"}:
            decision = heuristic_decision
            failure_class = heuristic_failure_class
        if decision == "RETRY":
            next_family = _infer_attempt_family(next_query.strip()) if next_query.strip() else attempt_family
            if next_family == attempt_family and not _is_meaningful_retry_justification(retry_justification):
                return {
                    "decision": "PIVOT",
                    "failure_class": failure_class,
                    "attempt_family": attempt_family,
                    "retry_justification": "",
                    "reason": "Retry in the same attempt family lacks a concrete technical reason for why it should work better than the previous try.",
                    "next_query": "",
                    "remaining_reflections": remaining,
                }
            if not next_query.strip() or next_query.strip() == current_query.strip():
                return {
                    "decision": "STOP",
                    "failure_class": failure_class,
                    "attempt_family": attempt_family,
                    "retry_justification": "",
                    "reason": "Retry requested but next_query missing/unchanged; stopping.",
                    "next_query": "",
                    "remaining_reflections": remaining,
                }
            return {
                "decision": "RETRY",
                "failure_class": failure_class,
                "attempt_family": next_family,
                "retry_justification": retry_justification,
                "reason": reason or "Retrying with a corrected query.",
                "next_query": _normalize_same_app_ssrf_loopback_ports(next_query.strip()),
                "remaining_reflections": max(0, remaining - 1),
            }

    if decision == "PIVOT":
        next_query = ""
        return {
            "decision": "PIVOT",
            "failure_class": failure_class if failure_class != "success" else "valid_attempt_no_signal",
            "attempt_family": attempt_family,
            "retry_justification": "",
            "reason": reason or "Current hypothesis looks exhausted; pivot recommended.",
            "next_query": next_query,
            "remaining_reflections": remaining,
        }

    return {
        "decision": "STOP",
        "failure_class": failure_class if failure_class != "success" else "valid_attempt_no_signal",
        "attempt_family": attempt_family,
        "retry_justification": "",
        "reason": reason or "Stopping bounded retry loop.",
        "next_query": "",
        "remaining_reflections": remaining,
    }


# Final lightweight validator used by the agents.  Reflection is deliberately
# limited to request/runtime validation; exploit progress belongs to the
# planner/checker, not this layer.
async def intra_reflection(
    *,
    recon_analyzer_output: str,
    exploit_analyzer_output: str,
    tool_runtime_result: str,
    original_task: str,
    current_query: str,
    remaining_reflections: int,
) -> Dict[str, Any]:
    del recon_analyzer_output, exploit_analyzer_output, original_task
    remaining = max(0, min(int(remaining_reflections), MAX_REFLECTIONS))
    runtime = tool_runtime_result or ""

    malformed = _looks_malformed_or_local_error(runtime) or bool(re.search(
        r"INVALID_TOOL_CALL|validation error|requires non-empty|must be a valid|missing required",
        runtime,
        re.IGNORECASE,
    ))
    transport_error = bool(re.search(
        r"curl:\s*\([0-9]+\)|timed out|connection refused|could not resolve|network is unreachable|gateway timeout",
        runtime,
        re.IGNORECASE,
    ))

    if malformed or transport_error:
        return {
            "decision": "STOP",
            "failure_class": "retryable_local_error",
            "retry_justification": "",
            "reason": "Tool/runtime error detected; leave correction to the planner without changing the attack strategy.",
            "next_query": "",
            "remaining_reflections": remaining,
        }

    return {
        "decision": "SUCCESS",
        "failure_class": "success",
        "retry_justification": "",
        "reason": "Tool call completed without a tool or transport error.",
        "next_query": "",
        "remaining_reflections": remaining,
    }
