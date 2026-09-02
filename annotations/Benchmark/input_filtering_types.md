# Input-Filtering Type Classification

This file assigns all 58 benchmark instances to the five input-filtering types used by the robustness analysis. The classification follows the mechanism exercised by the challenge's intended exploit path, rather than its vulnerability category.

## Classification Rules

- **Type 1 - No Filtering:** No explicit payload sanitization or validation is applied on the intended exploit path.
- **Type 2 - Blocklist Filtering:** Dangerous characters, tags, keywords, or path sequences are rejected or removed through pattern matching.
- **Type 3 - Canonicalized Blocklist Filtering:** Input is normalized, specifically through case folding, before blocklist evaluation.
- **Type 4 - Allowlist Filtering:** The application accepts only a predefined input format or file extension.
- **Type 5 - Replacement-Based Sanitization:** A targeted payload component is removed or rewritten before the transformed input is processed.

## Type 1 - No Filtering (38)

### XBEN (30)

- XBEN-001-24
- XBEN-002-24
- XBEN-003-24
- XBEN-005-24
- XBEN-019-24
- XBEN-020-24
- XBEN-025-24
- XBEN-026-24
- XBEN-031-24
- XBEN-032-24
- XBEN-033-24
- XBEN-036-24
- XBEN-037-24
- XBEN-038-24
- XBEN-039-24
- XBEN-040-24
- XBEN-041-24
- XBEN-043-24
- XBEN-052-24
- XBEN-053-24
- XBEN-058-24
- XBEN-070-24
- XBEN-076-24
- XBEN-090-24
- XBEN-091-24
- XBEN-093-24
- XBEN-094-24
- XBEN-101-24
- XBEN-102-24
- XBEN-104-24

### Vulhub (8)

- CVE-2019-10758
- CVE-2019-15107
- CVE-2021-26084
- CVE-2021-42013
- CVE-2022-22963
- CVE-2022-26134
- CVE-2023-22515
- CVE-2025-3248

The selected Vulhub instances reproduce vulnerable upstream versions without adding benchmark-specific blocklists, allowlists, canonicalization, or replacement-based sanitization to the exploited request path.

## Type 2 - Blocklist Filtering (13)

- **XBEN-010-24:** Rejects letters, digits, and angle brackets through a character blocklist (`src/app.py:69-74`).
- **XBEN-011-24:** Removes tags other than `image` and strips whitespace through regular-expression filtering (`src/app.py:68-70`).
- **XBEN-013-24:** Rejects the dangerous function names `alert` and `confirm` (`src/app.py:69-74`).
- **XBEN-016-24:** Rejects selected tags, event handlers, quotes, and spaces (`src/app.py:68-73`).
- **XBEN-018-24:** Rejects tags matching a regular-expression blocklist (`src/app.py:70-75`).
- **XBEN-028-24:** Rejects path input containing the traversal sequence `..` (`app/website/post.php:2-9`).
- **XBEN-045-24:** Rejects command input containing `<`, `>`, `|`, or `&` (`app/app.py:16-20`).
- **XBEN-046-24:** Removes explicitly blocked HTML tags and slash/question-mark characters (`src/app.py:69-75`).
- **XBEN-047-24:** Removes quotes, angle brackets, and non-image URL patterns (`src/app.py:69-71`).
- **XBEN-049-24:** Removes the target `XSS` string and `script` tags (`src/app.py:68-69`).
- **XBEN-050-24:** Removes every HTML tag except `body` (`src/app.py:68-69`).
- **XBEN-051-24:** Rejects selected tags, event handlers, quotes, and slashes (`src/app.py:69-74`).
- **XBEN-087-24:** Rejects angle brackets, quotes, uppercase letters, and square brackets (`src/app.py:68-74`).

## Type 3 - Canonicalized Blocklist Filtering (2)

- **XBEN-004-24:** Case-folds input with `msg.lower()` before evaluating a keyword and event-handler blocklist (`src/app.py:69-74`).
- **XBEN-008-24:** Case-folds input with `msg.lower()` before evaluating a keyword and event-handler blocklist (`src/app.py:68-73`).

## Type 4 - Allowlist Filtering (3)

- **XBEN-006-24:** The challenge defines a constrained SQL-query input policy intended as an allowlist and filters SQL control words before query execution (`app/main.py:39-58`; challenge README).
- **XBEN-024-24:** Uploaded profile images are accepted only when their extension belongs to `png`, `jpg`, `jpeg`, or `gif` (`app/app.py:8-9,24-25,86-90`).
- **XBEN-029-24:** Invoice uploads are accepted only when the filename satisfies the required PDF format (`app/website/upload.php:18-46`).

## Type 5 - Replacement-Based Sanitization (2)

- **XBEN-012-24:** Rewrites the submitted payload by removing the target `XSS` string and HTML-tag prefixes before rendering (`src/app.py:69-70`).
- **XBEN-017-24:** Rewrites the submitted payload by removing the target `XSS` string before rendering (`src/app.py:69`).

## Coverage Check

| Type | Challenges |
|---|---:|
| Type 1 | 38 |
| Type 2 | 13 |
| Type 3 | 2 |
| Type 4 | 3 |
| Type 5 | 2 |
| **Total** | **58** |

