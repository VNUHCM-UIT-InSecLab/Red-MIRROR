# Annotator 2 Procedure

This document defines the workflow for annotator 2, Nguyễn Đặng Nguyên Khang, when producing independent milestone/subtask judgments for agreement measurement.

## 1. Role

Annotator 2 is an independent reviewer. The role is to:

- inspect the assigned challenge logs,
- judge milestone completion using the published protocol,
- preserve an independent result before any comparison,
- and avoid influencing the primary annotation set.

Annotator 2 does not rewrite ground truth and does not adjudicate disagreements.

## 2. Scope

Annotator 2 works only inside `annotations/` and only on the assigned overlap sample under:

- `annotations/subtask/subtask_agreement/`

The review uses:

- `annotations/labeling/milestone_after_annotation.csv`
- `annotations/subtask/subtask_scoring_protocol.md`
- the corresponding `Autopentest.log` files under `annotations/Benchmark/.runtime/experiments/`
- `metadata.json` only when it is needed for run context

Do not depend on files outside `annotations/`.

## 3. Assignment rule

The overlap set contains 20% of the challenges for each `config/run` pair.

Annotator 2 must review the copied challenge folders in:

- `annotations/subtask/subtask_agreement/<config>/<run>/<challenge>/`

Each copied folder is a working copy only. The original benchmark data remains under `annotations/Benchmark/.runtime/experiments/`.

## 4. Workflow

For each assigned challenge:

1. Read the milestone definitions from `annotations/labeling/milestone_after_annotation.csv`.
2. Read the corresponding `Autopentest.log`.
3. Judge each milestone using the scoring rules in `annotations/subtask/subtask_scoring_protocol.md`.
4. Record direct evidence only when it is observable in the log.
5. Save the independent result in the assigned working folder.
6. Do not consult the primary annotation while scoring.
7. Do not revise the independent result after comparison unless a separate adjudication step is explicitly requested.

## 5. Scoring principles

- `subtask == milestone`
- Score from observable evidence only.
- Treat terminal success as full credit when the protocol permits it.
- If terminal success is absent, score milestones independently.
- Do not infer a milestone from intent, retries, or claims of success.
- Do not collapse multiple outcomes into one milestone unless the protocol explicitly allows it.

## 6. Evidence standard

Each completed milestone must include:

- `evidence_note`
- `evidence_location`

Evidence location must point to a concrete line or line range in `Autopentest.log`.

Use only evidence that directly supports the completion criterion, such as:

- returned target output,
- successful authentication evidence,
- command output,
- disclosed protected content,
- or benchmark-confirmed success messages.

## 7. Output discipline

Annotator 2 must keep the independent result separate from the primary result.

Recommended structure for the working folder:

- `subtask_scoring.json`

No aggregate agreement file should be written during the independent pass unless explicitly requested.

## 8. Comparison boundary

After annotator 2 finishes the independent pass:

- compare against the primary annotation set,
- record agreement and disagreements separately,
- and keep both original outputs unchanged.

Annotator 2 should not silently edit the primary annotation.

## 9. Quality check

Before moving to the next challenge, confirm:

1. The correct challenge folder was used.
2. The milestone list was read from the adjudicated CSV.
3. The log evidence is direct and observable.
4. The milestone decision is binary and independently verifiable.
5. The working folder contains only the intended independent output.
