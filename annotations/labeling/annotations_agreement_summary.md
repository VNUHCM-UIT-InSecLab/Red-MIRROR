# Inter-Annotator Agreement Summary for Outcome-Oriented Milestones

## Scope

This agreement analysis compares the primary annotations in `annotations/labeling/annotations.csv` with the independent annotations in `annotations/labeling/annotations_of_annotator2.csv`.

- Frozen subset size: 20 benchmark instances.
- Sampling seed: 20260809.
- Unit of analysis: outcome-oriented milestone.
- Matching rule: semantic one-to-one matching. A milestone is counted as matched only when the primary and secondary annotations describe the same independently verifiable outcome, regardless of wording or order.
- Split/merge cases are recorded as disagreement cases and are not counted as full one-to-one matches.

## Agreement counts

| Metric | Value |
|---|---:|
| Primary milestones | 91 |
| Secondary milestones | 76 |
| Matched milestones | 68 |
| Unmatched primary milestones | 23 |
| Unmatched secondary milestones | 8 |
| Precision | 0.895 |
| Recall | 0.747 |
| F1 | 0.814 |

## Formula

```text
Precision = matched secondary milestones / total secondary milestones
          = 68 / 76
          = 0.895

Recall    = matched primary milestones / total primary milestones
          = 68 / 91
          = 0.747

F1        = 2 * Precision * Recall / (Precision + Recall)
          = 0.814
```

## Per-instance agreement

| Challenge ID | Primary | Secondary | Matched | Precision | Recall | F1 | Main disagreement pattern |
|---|---:|---:|---:|---:|---:|---:|---|
| XBEN-005-24 | 5 | 4 | 3 | 0.750 | 0.600 | 0.667 | Secondary omits separate default-credential discovery and weakens privilege-attribute identification. |
| XBEN-013-24 | 3 | 3 | 3 | 1.000 | 1.000 | 1.000 | None. |
| XBEN-019-24 | 3 | 3 | 3 | 1.000 | 1.000 | 1.000 | Same outcomes, different order. |
| XBEN-039-24 | 3 | 3 | 3 | 1.000 | 1.000 | 1.000 | None. |
| XBEN-047-24 | 6 | 3 | 2 | 0.667 | 0.333 | 0.444 | Secondary merges multiple filtering and delivery outcomes. |
| XBEN-053-24 | 5 | 4 | 4 | 1.000 | 0.800 | 0.889 | Secondary omits separate surface-identification milestone. |
| XBEN-058-24 | 4 | 3 | 3 | 1.000 | 0.750 | 0.857 | Secondary merges client-controlled tenant ID identification with cross-tenant access. |
| XBEN-004-24 | 6 | 3 | 2 | 0.667 | 0.333 | 0.444 | Secondary merges tag, handler, quote, and execution-vector outcomes. |
| XBEN-008-24 | 6 | 4 | 3 | 0.750 | 0.500 | 0.600 | Secondary merges multiple filter-characterization outcomes. |
| XBEN-012-24 | 6 | 4 | 4 | 1.000 | 0.667 | 0.800 | Secondary merges tag-prefix transformation and attribute-breakout outcomes. |
| XBEN-029-24 | 6 | 6 | 6 | 1.000 | 1.000 | 1.000 | None. |
| XBEN-038-24 | 4 | 4 | 4 | 1.000 | 1.000 | 1.000 | None. |
| XBEN-091-24 | 4 | 4 | 4 | 1.000 | 1.000 | 1.000 | None. |
| XBEN-094-24 | 4 | 4 | 4 | 1.000 | 1.000 | 1.000 | None. |
| XBEN-104-24 | 5 | 5 | 5 | 1.000 | 1.000 | 1.000 | None. |
| XBEN-010-24 | 4 | 5 | 3 | 0.600 | 0.750 | 0.667 | Secondary splits non-alphanumeric execution construction and separates flag disclosure. |
| XBEN-087-24 | 5 | 5 | 3 | 0.600 | 0.600 | 0.600 | Secondary merges lexical and quote constraints, and adds a separate flag-disclosure milestone. |
| CVE-2021-26084 | 4 | 3 | 3 | 1.000 | 0.750 | 0.857 | Secondary treats command execution as the terminal Vulhub objective instead of adding a separate completion milestone. |
| CVE-2022-22963 | 4 | 3 | 3 | 1.000 | 0.750 | 0.857 | Secondary treats marker-based command execution as the terminal objective. |
| CVE-2025-3248 | 4 | 3 | 3 | 1.000 | 0.750 | 0.857 | Secondary treats validation-error command output as the terminal objective. |
