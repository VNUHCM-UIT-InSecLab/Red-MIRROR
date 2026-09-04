# Repeated-Run Results

Recomputed directly from the final `metadata.json`, `subtask_scoring.json`, and `Autopentest.log` files under `annotations/Benchmark/.runtime/experiments` on 2026-09-01. No statistic from the previous report was used as input.

## Reporting Protocol

- Every configuration has three runs of 50 XBOW challenges and 8 Vulhub CVEs.
- Success is determined by `metadata.json.exploit_status == "success"`.
- Subtask-completion rate is recalculated per run from milestone `completed` flags and the final adjudicated milestone totals.
- `Solved` and rates are reported as mean ± sample standard deviation across three runs. Variance is the unbiased sample variance of run-level percentages.
- The 95% confidence interval is a two-sided Student t interval with `n=3` and `df=2`.
- TTE is the total number of tasks performed by the system before successful exploitation and is defined only for successful challenges.

## Annotation Ground Truth and Validation

- Final inventory: **251 milestones** across 58 challenges: **223 XBOW** milestones and **28 Vulhub** milestones.
- Included artifacts: **30 configuration/run folders** and **1,740 challenge results**.
- Every run contains the same authoritative 58 challenge IDs and both required JSON files.
- Every scoring file has the authoritative per-challenge milestone count; `subtask_total`, `subtask_completed`, and `subtask_rate` agree with its milestone flags.
- Every metadata success has complete milestone attainment after terminal-success normalization.
- The five input-filtering groups cover all 58 challenges exactly once.

## RQ1: Full System versus Baselines

### Difficulty Breakdown (XBOW)

| Difficulty / metric | Red-MIRROR | VulnBot | PentestAgent | AutoPT | Total |
|---|---:|---:|---:|---:|---:|
| Level 1 - Solved | 21.00 ± 2.00 | 15.33 ± 1.53 | 15.33 ± 2.52 | 14.00 ± 3.61 | 23 |
| Level 1 - Success rate | 91.30% ± 8.70% | 66.67% ± 6.64% | 66.67% ± 10.94% | 60.87% ± 15.68% | 23 |
| Level 2 - Solved | 16.67 ± 0.58 | 3.00 ± 2.00 | 7.00 ± 5.29 | 6.67 ± 0.58 | 22 |
| Level 2 - Success rate | 75.76% ± 2.62% | 13.64% ± 9.09% | 31.82% ± 24.05% | 30.30% ± 2.62% | 22 |
| Level 3 - Solved | 3.33 ± 0.58 | 0.00 ± 0.00 | 1.00 ± 1.00 | 0.67 ± 0.58 | 5 |
| Level 3 - Success rate | 66.67% ± 11.55% | 0.00% ± 0.00% | 20.00% ± 20.00% | 13.33% ± 11.55% | 5 |
| XBOW Overall - Solved | 41.00 ± 1.73 | 18.33 ± 0.58 | 23.33 ± 6.66 | 21.33 ± 3.79 | 50 |
| XBOW Overall - Success rate | 82.00% ± 3.46% | 36.67% ± 1.15% | 46.67% ± 13.32% | 42.67% ± 7.57% | 50 |

### Subtask Completion by Vulnerability Category (All 58 Challenges)

| Vulnerability category | Red-MIRROR | VulnBot | PentestAgent | AutoPT |
|---|---:|---:|---:|---:|
| SQL Injection (SQLi) | 50.00% ± 0.00% | 31.82% ± 25.31% | 37.88% ± 17.21% | 22.73% ± 4.55% |
| Cross-Site Scripting (XSS) | 97.12% ± 2.57% | 28.81% ± 3.56% | 49.79% ± 25.07% | 41.98% ± 6.17% |
| Command Injection & RCE | 61.40% ± 8.04% | 42.69% ± 2.68% | 38.60% ± 20.23% | 53.22% ± 3.65% |
| SSTI | 93.65% ± 11.00% | 38.10% ± 14.29% | 60.32% ± 21.47% | 28.57% ± 25.20% |
| IDOR & Access Control | 84.95% ± 3.72% | 43.01% ± 8.12% | 68.82% ± 13.04% | 31.18% ± 7.45% |
| Authentication Failures | 77.97% ± 5.87% | 43.50% ± 5.45% | 50.28% ± 11.54% | 37.85% ± 6.42% |
| SSRF | 83.33% ± 28.87% | 75.00% ± 8.33% | 94.44% ± 9.62% | 100.00% ± 0.00% |
| Path Traversal & LFI | 71.43% ± 8.25% | 47.62% ± 12.60% | 55.56% ± 9.91% | 53.97% ± 13.75% |
| XXE | 100.00% ± 0.00% | 75.00% ± 43.30% | 0.00% ± 0.00% | 100.00% ± 0.00% |
| Cryptographic Failures | 0.00% ± 0.00% | 8.33% ± 14.43% | 0.00% ± 0.00% | 16.67% ± 28.87% |
| Overall (58) | 78.35% ± 2.56% | 39.58% ± 3.93% | 49.27% ± 16.04% | 45.82% ± 4.20% |

### Aggregate Results

| Benchmark / metric | Red-MIRROR | VulnBot | PentestAgent | AutoPT |
|---|---:|---:|---:|---:|
| **XBOW (50 challenges/run)** |  |  |  |  |
| Solved | 41.00 ± 1.73 | 18.33 ± 0.58 | 23.33 ± 6.66 | 21.33 ± 3.79 |
| Success rate | 82.00% ± 3.46% | 36.67% ± 1.15% | 46.67% ± 13.32% | 42.67% ± 7.57% |
| Success-rate variance | 12.00 | 1.33 | 177.33 | 57.33 |
| Success-rate 95% CI | [73.39%, 90.61%] | [33.80%, 39.54%] | [13.59%, 79.75%] | [23.86%, 61.48%] |
| Subtask-completion rate | 82.81% ± 2.85% | 41.85% ± 2.55% | 53.81% ± 16.61% | 46.64% ± 5.93% |
| Subtask-rate variance | 8.11 | 6.50 | 275.90 | 35.19 |
| Subtask-rate 95% CI | [75.74%, 89.88%] | [35.52%, 48.19%] | [12.55%, 95.07%] | [31.90%, 61.37%] |
| |  |  |  |  |
| **Vulhub (8 challenges/run)** |  |  |  |  |
| Solved | 2.33 ± 0.58 | 1.00 ± 1.00 | 0.00 ± 0.00 | 1.67 ± 1.15 |
| Success rate | 29.17% ± 7.22% | 12.50% ± 12.50% | 0.00% ± 0.00% | 20.83% ± 14.43% |
| Success-rate variance | 52.08 | 156.25 | 0.00 | 208.33 |
| Success-rate 95% CI | [11.24%, 47.09%] | [-18.55%, 43.55%] | [0.00%, 0.00%] | [-15.02%, 56.69%] |
| Subtask-completion rate | 42.86% ± 3.57% | 21.43% ± 15.57% | 13.10% ± 11.48% | 39.29% ± 14.29% |
| Subtask-rate variance | 12.76 | 242.35 | 131.80 | 204.08 |
| Subtask-rate 95% CI | [33.99%, 51.73%] | [-17.24%, 60.10%] | [-15.42%, 41.61%] | [3.80%, 74.77%] |
| |  |  |  |  |
| **Overall (58 challenges/run)** |  |  |  |  |
| Solved | 43.33 ± 1.53 | 19.33 ± 1.15 | 23.33 ± 6.66 | 23.00 ± 2.65 |
| Success rate | 74.71% ± 2.63% | 33.33% ± 1.99% | 40.23% ± 11.48% | 39.66% ± 4.56% |
| Success-rate variance | 6.94 | 3.96 | 131.79 | 20.81 |
| Success-rate 95% CI | [68.17%, 81.26%] | [28.39%, 38.28%] | [11.71%, 68.75%] | [28.32%, 50.99%] |
| Subtask-completion rate | 78.35% ± 2.56% | 39.58% ± 3.93% | 49.27% ± 16.04% | 45.82% ± 4.20% |
| Subtask-rate variance | 6.56 | 15.45 | 257.19 | 17.62 |
| Subtask-rate 95% CI | [71.99%, 84.72%] | [29.81%, 49.34%] | [9.43%, 89.11%] | [35.39%, 56.24%] |

The recorded total costs, aggregated from the OpenCode dashboard after each configuration completed its runs, were **$24.59** for Red-MIRROR, **$8.46** for VulnBot, **$8.59** for PentestAgent, and **$8.64** for AutoPT.

From these totals, the average cost per challenge is calculated as `total_cost / 174`, where 174 corresponds to three runs of 58 challenges. This yields **$0.1413** for Red-MIRROR, **$0.0486** for VulnBot, **$0.0494** for PentestAgent, and **$0.0497** for AutoPT.

Although the full Red-MIRROR configuration costs approximately three times as much per challenge as the baseline systems, this additional cost trades off against substantially greater testing effectiveness, as reflected in its clearly higher overall success rate.

## RQ2: Model Variants

| Benchmark / metric | Qwen2.5-14B (base) | Qwen2.5-14B (FT) | Red-MIRROR |
|---|---:|---:|---:|
| **XBOW (50 challenges/run)** |  |  |  |
| Solved | 0.00 ± 0.00 | 2.00 ± 1.00 | 41.00 ± 1.73 |
| Success rate | 0.00% ± 0.00% | 4.00% ± 2.00% | 82.00% ± 3.46% |
| Success-rate variance | 0.00 | 4.00 | 12.00 |
| Success-rate 95% CI | [0.00%, 0.00%] | [-0.97%, 8.97%] | [73.39%, 90.61%] |
| Subtask-completion rate | 2.99% ± 0.26% | 6.13% ± 2.02% | 82.81% ± 2.85% |
| Subtask-rate variance | 0.07 | 4.09 | 8.11 |
| Subtask-rate 95% CI | [2.35%, 3.63%] | [1.11%, 11.15%] | [75.74%, 89.88%] |
| |  |  |  |
| **Vulhub (8 challenges/run)** |  |  |  |
| Solved | 0.00 ± 0.00 | 0.00 ± 0.00 | 2.33 ± 0.58 |
| Success rate | 0.00% ± 0.00% | 0.00% ± 0.00% | 29.17% ± 7.22% |
| Success-rate variance | 0.00 | 0.00 | 52.08 |
| Success-rate 95% CI | [0.00%, 0.00%] | [0.00%, 0.00%] | [11.24%, 47.09%] |
| Subtask-completion rate | 2.38% ± 2.06% | 10.71% ± 6.19% | 42.86% ± 3.57% |
| Subtask-rate variance | 4.25 | 38.27 | 12.76 |
| Subtask-rate 95% CI | [-2.74%, 7.50%] | [-4.65%, 26.08%] | [33.99%, 51.73%] |
| |  |  |  |
| **Overall (58 challenges/run)** |  |  |  |
| Solved | 0.00 ± 0.00 | 2.00 ± 1.00 | 43.33 ± 1.53 |
| Success rate | 0.00% ± 0.00% | 3.45% ± 1.72% | 74.71% ± 2.63% |
| Success-rate variance | 0.00 | 2.97 | 6.94 |
| Success-rate 95% CI | [0.00%, 0.00%] | [-0.83%, 7.73%] | [68.17%, 81.26%] |
| Subtask-completion rate | 2.92% ± 0.23% | 6.64% ± 1.22% | 78.35% ± 2.56% |
| Subtask-rate variance | 0.05 | 1.48 | 6.56 |
| Subtask-rate 95% CI | [2.35%, 3.49%] | [3.62%, 9.66%] | [71.99%, 84.72%] |

## RQ3: Component Ablations

| Benchmark / metric | Red-MIRROR | w/o RAG | w/o SRMM | w/o Reflection | Core Only |
|---|---:|---:|---:|---:|---:|
| **XBOW (50 challenges/run)** |  |  |  |  |  |
| Solved | 41.00 ± 1.73 | 30.00 ± 2.00 | 23.33 ± 0.58 | 24.00 ± 1.00 | 20.00 ± 2.00 |
| Success rate | 82.00% ± 3.46% | 60.00% ± 4.00% | 46.67% ± 1.15% | 48.00% ± 2.00% | 40.00% ± 4.00% |
| Success-rate variance | 12.00 | 16.00 | 1.33 | 4.00 | 16.00 |
| Success-rate 95% CI | [73.39%, 90.61%] | [50.06%, 69.94%] | [43.80%, 49.54%] | [43.03%, 52.97%] | [30.06%, 49.94%] |
| Subtask-completion rate | 82.81% ± 2.85% | 63.53% ± 2.70% | 49.93% ± 2.07% | 52.91% ± 1.62% | 46.49% ± 3.42% |
| Subtask-rate variance | 8.11 | 7.31 | 4.29 | 2.61 | 11.73 |
| Subtask-rate 95% CI | [75.74%, 89.88%] | [56.81%, 70.24%] | [44.78%, 55.07%] | [48.90%, 56.93%] | [37.98%, 55.00%] |
| |  |  |  |  |  |
| **Vulhub (8 challenges/run)** |  |  |  |  |  |
| Solved | 2.33 ± 0.58 | 0.00 ± 0.00 | 0.33 ± 0.58 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| Success rate | 29.17% ± 7.22% | 0.00% ± 0.00% | 4.17% ± 7.22% | 0.00% ± 0.00% | 0.00% ± 0.00% |
| Success-rate variance | 52.08 | 0.00 | 52.08 | 0.00 | 0.00 |
| Success-rate 95% CI | [11.24%, 47.09%] | [0.00%, 0.00%] | [-13.76%, 22.09%] | [0.00%, 0.00%] | [0.00%, 0.00%] |
| Subtask-completion rate | 42.86% ± 3.57% | 19.05% ± 7.43% | 10.71% ± 9.45% | 11.90% ± 5.46% | 14.29% ± 0.00% |
| Subtask-rate variance | 12.76 | 55.27 | 89.29 | 29.76 | 0.00 |
| Subtask-rate 95% CI | [33.99%, 51.73%] | [0.58%, 37.52%] | [-12.76%, 34.19%] | [-1.65%, 25.46%] | [14.29%, 14.29%] |
| |  |  |  |  |  |
| **Overall (58 challenges/run)** |  |  |  |  |  |
| Solved | 43.33 ± 1.53 | 30.00 ± 2.00 | 23.67 ± 0.58 | 24.00 ± 1.00 | 20.00 ± 2.00 |
| Success rate | 74.71% ± 2.63% | 51.72% ± 3.45% | 40.80% ± 1.00% | 41.38% ± 1.72% | 34.48% ± 3.45% |
| Success-rate variance | 6.94 | 11.89 | 0.99 | 2.97 | 11.89 |
| Success-rate 95% CI | [68.17%, 81.26%] | [43.16%, 60.29%] | [38.33%, 43.28%] | [37.10%, 45.66%] | [25.92%, 43.05%] |
| Subtask-completion rate | 78.35% ± 2.56% | 58.57% ± 3.01% | 45.55% ± 1.40% | 48.34% ± 1.51% | 42.90% ± 3.04% |
| Subtask-rate variance | 6.56 | 9.05 | 1.96 | 2.28 | 9.26 |
| Subtask-rate 95% CI | [71.99%, 84.72%] | [51.09%, 66.04%] | [42.08%, 49.03%] | [44.59%, 52.09%] | [35.34%, 50.45%] |

### Subtask Completion by Vulnerability Category

| Vulnerability category | Red-MIRROR | w/o RAG | w/o SRMM | w/o Reflection | Core Only |
|---|---:|---:|---:|---:|---:|
| SQL Injection (SQLi) | 50.00% ± 0.00% | 42.42% ± 10.50% | 24.24% ± 2.62% | 24.24% ± 2.62% | 37.88% ± 5.25% |
| Cross-Site Scripting (XSS) | 97.12% ± 2.57% | 86.83% ± 4.67% | 70.78% ± 1.89% | 76.95% ± 3.56% | 62.55% ± 7.94% |
| Command Injection & RCE | 61.40% ± 8.04% | 38.60% ± 7.65% | 22.22% ± 9.66% | 24.56% ± 10.96% | 16.37% ± 4.05% |
| SSTI | 93.65% ± 11.00% | 38.10% ± 0.00% | 38.10% ± 0.00% | 38.10% ± 0.00% | 50.79% ± 11.98% |
| IDOR & Access Control | 84.95% ± 3.72% | 38.71% ± 5.59% | 33.33% ± 7.45% | 37.63% ± 7.45% | 39.78% ± 10.37% |
| Authentication Failures | 77.97% ± 5.87% | 36.72% ± 0.98% | 29.94% ± 5.95% | 32.77% ± 6.42% | 36.72% ± 3.91% |
| SSRF | 83.33% ± 28.87% | 80.56% ± 4.81% | 61.11% ± 24.06% | 55.56% ± 19.25% | 36.11% ± 4.81% |
| Path Traversal & LFI | 71.43% ± 8.25% | 65.08% ± 7.27% | 30.16% ± 13.75% | 31.75% ± 2.75% | 20.63% ± 7.27% |
| XXE | 100.00% ± 0.00% | 100.00% ± 0.00% | 75.00% ± 43.30% | 100.00% ± 0.00% | 25.00% ± 0.00% |
| Cryptographic Failures | 0.00% ± 0.00% | 0.00% ± 0.00% | 0.00% ± 0.00% | 0.00% ± 0.00% | 0.00% ± 0.00% |
| XBOW Overall | 82.81% ± 2.85% | 63.53% ± 2.70% | 49.93% ± 2.07% | 52.91% ± 1.62% | 46.49% ± 3.42% |
| Vulhub Overall | 42.86% ± 3.57% | 19.05% ± 7.43% | 10.71% ± 9.45% | 11.90% ± 5.46% | 14.29% ± 0.00% |
| Overall (58) | 78.35% ± 2.56% | 58.57% ± 3.01% | 45.55% ± 1.40% | 48.34% ± 1.51% | 42.90% ± 3.04% |

### TTE by Input-Filtering Type

TTE is calculated only for successful challenges and represents the total number of tasks performed by the system before successful exploitation.

| Type / metric | Red-MIRROR | w/o RAG | w/o SRMM | w/o Reflection | Core Only |
|---|---:|---:|---:|---:|---:|
| Type 1 - Solved | 27.00 ± 1.00 | 16.67 ± 1.15 | 13.33 ± 0.58 | 13.67 ± 1.53 | 10.67 ± 0.58 |
| Type 1 - Success rate | 71.05% ± 2.63% | 43.86% ± 3.04% | 35.09% ± 1.52% | 35.96% ± 4.02% | 28.07% ± 1.52% |
| Type 1 - TTE | 7.36 ± 1.00 | 9.39 ± 3.20 | 7.67 ± 1.13 | 6.43 ± 0.94 | 6.90 ± 1.50 |
| Type 2 - Solved | 10.67 ± 0.58 | 8.33 ± 1.15 | 6.33 ± 0.58 | 6.67 ± 1.53 | 5.00 ± 1.00 |
| Type 2 - Success rate | 82.05% ± 4.44% | 64.10% ± 8.88% | 48.72% ± 4.44% | 51.28% ± 11.75% | 38.46% ± 7.69% |
| Type 2 - TTE | 5.47 ± 0.68 | 5.63 ± 0.78 | 7.03 ± 2.14 | 6.91 ± 0.57 | 5.42 ± 0.37 |
| Type 3 - Solved | 2.00 ± 0.00 | 2.00 ± 0.00 | 1.67 ± 0.58 | 1.67 ± 0.58 | 2.00 ± 0.00 |
| Type 3 - Success rate | 100.00% ± 0.00% | 100.00% ± 0.00% | 83.33% ± 28.87% | 83.33% ± 28.87% | 100.00% ± 0.00% |
| Type 3 - TTE | 5.00 ± 1.00 | 5.00 ± 0.50 | 7.17 ± 2.02 | 9.00 ± 3.46 | 5.83 ± 1.44 |
| Type 4 - Solved | 1.67 ± 0.58 | 1.00 ± 0.00 | 0.33 ± 0.58 | 0.00 ± 0.00 | 0.67 ± 0.58 |
| Type 4 - Success rate | 55.56% ± 19.25% | 33.33% ± 0.00% | 11.11% ± 19.25% | 0.00% ± 0.00% | 22.22% ± 19.25% |
| Type 4 - TTE | 5.83 ± 1.44 | 7.00 ± 1.73 | 15.00 (one run) | -- | 6.00 ± 1.41 |
| Type 5 - Solved | 2.00 ± 0.00 | 2.00 ± 0.00 | 2.00 ± 0.00 | 2.00 ± 0.00 | 1.67 ± 0.58 |
| Type 5 - Success rate | 100.00% ± 0.00% | 100.00% ± 0.00% | 100.00% ± 0.00% | 100.00% ± 0.00% | 83.33% ± 28.87% |
| Type 5 - TTE | 6.00 ± 0.87 | 5.50 ± 1.00 | 5.83 ± 0.58 | 5.50 ± 0.87 | 6.33 ± 1.53 |
| Overall - Solved | 43.33 ± 1.53 | 30.00 ± 2.00 | 23.67 ± 0.58 | 24.00 ± 1.00 | 20.00 ± 2.00 |
| Overall - Success rate | 74.71% ± 2.63% | 51.72% ± 3.45% | 40.80% ± 1.00% | 41.38% ± 1.72% | 34.48% ± 3.45% |
| Overall - TTE | 6.67 ± 0.71 | 7.68 ± 2.00 | 7.50 ± 0.58 | 6.59 ± 0.41 | 6.36 ± 0.84 |

The total costs for the five DeepSeek configurations, likewise aggregated from the OpenCode dashboard after each configuration completed its runs, were **$24.59** for Red-MIRROR, **$15.13** for w/o RAG, **$13.83** for w/o SRMM, **$13.71** for w/o Reflection, and **$8.86** for Core Only.

From these totals, the average cost per challenge is calculated using `total_cost / 174`. This yields **$0.1413** for Red-MIRROR, **$0.0870** for w/o RAG, **$0.0795** for w/o SRMM, **$0.0788** for w/o Reflection, and **$0.0509** for Core Only.

Although the full Red-MIRROR configuration costs nearly three times as much per challenge as Core Only, this additional cost trades off against substantially greater testing effectiveness, with the full configuration achieving a clearly higher overall success rate than every ablated configuration.
