# Exploratory: off-the-shelf parser (tree-sitter-bash) ablation

Deviation 9 in docs/research/PREREGISTRATION.md. Pack `ts=front:MAP:with:tokplus:policies/claude-code.json`, MAP from `bench/tools/ts_front.py` (tree-sitter 0.26.0, tree-sitter-bash 0.25.1). Analyzer hash 6809d27d unchanged. Lines below are copied verbatim from agbench output; only aggregates are shown.

Front end over the real-traffic corpora: 875399 distinct Bash commands, 6158 failed to parse (fail closed).

## heldout-b

| Pack | Recall | False-positive rate | Exact | Eval errors |
|---|---|---|---|---|
| facts | 72/80 (90%) | 4/70 (6%) | 138/150 (92%) | 0 |
| tokplus | 69/80 (86%) | 4/70 (6%) | 135/150 (90%) | 0 |
| ts | 72/80 (90%) | 4/70 (6%) | 138/150 (92%) | 0 |


## adaptive

| Pack | Recall | False-positive rate | Exact | Eval errors |
|---|---|---|---|---|
| facts | 39/50 (78%) | 0/3 (0%) | 42/53 (79%) | 0 |
| tokplus | 37/50 (74%) | 0/3 (0%) | 40/53 (75%) | 0 |
| ts | 39/50 (78%) | 0/3 (0%) | 42/53 (79%) | 0 |


## actions

| Pack | Recall | False-positive rate | Exact | Eval errors |
|---|---|---|---|---|
| facts | 133/133 (100%) | 0/95 (0%) | 228/228 (100%) | 0 |
| tokplus | 129/133 (97%) | 0/95 (0%) | 224/228 (98%) | 0 |
| ts | 130/133 (98%) | 0/95 (0%) | 225/228 (99%) | 0 |


## codex-bash

| Pack | Recall | False-positive rate | Exact | Eval errors |
|---|---|---|---|---|
| facts | 2/3 (67%) | 0/37 (0%) | 39/40 (98%) | 0 |
| tokplus | 2/3 (67%) | 0/37 (0%) | 39/40 (98%) | 0 |
| ts | 2/3 (67%) | 0/37 (0%) | 39/40 (98%) | 0 |


Held-out B with the first front-end version (before the process-substitution fix): ts 71/80 recall, 4/70 FPR, 137/150 exact.

## Frozen Claude Code corpus (in-sample)

| Pack | Interrupted | Denied | Approval | Shell calls interrupted |
|---|---|---|---|---|
| v1 | 249/27927 (1%) | 3 | 246 | 246/20284 (1%) |
| regex | 1396/27927 (5%) | 286 | 1110 | 1396/20284 (7%) |
| tuned | 544/27927 (2%) | 260 | 284 | 544/20284 (3%) |
| vocab | 738/27927 (3%) | 422 | 316 | 738/20284 (4%) |
| facts | 556/27927 (2%) | 224 | 332 | 556/20284 (3%) |
| tokplus | 1357/27927 (5%) | 163 | 1194 | 1357/20284 (7%) |
| ts | 667/27927 (2%) | 192 | 475 | 667/20284 (3%) |

## SWE-chat (417 developers)

| | Agents | Shell calls | v1 | regex | tuned | vocab | facts | tok | tokplus | ts |
|---|---|---|---|---|---|---|---|---|---|---|
| **Pooled** | | 640530 | 0.83% | 3.74% | 2.57% | 3.16% | 1.98% | 4.73% | 3.82% | 2.05% |
| **Macro mean** | | | 0.86% | 3.04% | 2.02% | 2.33% | 2.21% | 4.48% | 3.75% | 2.26% |

- **facts vs tokplus**: facts stops fewer calls for 251 developers, more for 28, ties 138; one-sided sign test p = 2.803e-46.
- **facts vs vocab**: facts stops fewer calls for 166 developers, more for 86, ties 165; one-sided sign test p = 2.623e-07.
- **facts vs tuned**: facts stops fewer calls for 119 developers, more for 123, ties 175; one-sided sign test p = 0.626.
- **ts vs tokplus**: ts stops fewer calls for 245 developers, more for 36, ties 136; one-sided sign test p = 1.107e-39.
- **ts vs vocab**: ts stops fewer calls for 163 developers, more for 89, ties 165; one-sided sign test p = 1.827e-06.
- **ts vs tuned**: ts stops fewer calls for 120 developers, more for 128, ties 169; one-sided sign test p = 0.7161.
- **facts vs ts**: facts stops fewer calls for 68 developers, more for 21, ties 328; one-sided sign test p = 2.993e-07.

    SWE ts-facts: dev=417, median=0.000, macro=0.048, macro_ci=(0.005, 0.091), pooled=0.066, pooled_ci=(0.011, 0.151), pooled_wo_top10=0.083, top10_share=0.406
    SWE ts-tokplus: dev=417, median=-0.460, macro=-1.486, macro_ci=(-1.769, -1.237), pooled=-1.774, pooled_ci=(-2.186, -1.458), pooled_wo_top10=-1.977, top10_share=0.406
    SWE ts-vocab: dev=417, median=0.000, macro=-0.067, macro_ci=(-0.35, 0.245), pooled=-1.111, pooled_ci=(-2.343, -0.059), pooled_wo_top10=-0.714, top10_share=0.406

## Self-published, primary

13 developers with at least 50 shell calls

| | Agents | Shell calls | v1 | regex | tuned | vocab | facts | tok | tokplus | ts |
|---|---|---|---|---|---|---|---|---|---|---|
| **Pooled** | | 453036 | 0.48% | 2.24% | 1.09% | 1.18% | 1.30% | 2.04% | 1.88% | 1.33% |
| **Macro mean** | | | 0.88% | 2.89% | 1.38% | 1.56% | 2.33% | 3.30% | 3.05% | 2.37% |

- **facts vs tokplus**: facts stops fewer calls for 10 developers, more for 0, ties 3; one-sided sign test p = 0.0009766.
- **facts vs vocab**: facts stops fewer calls for 2 developers, more for 8, ties 3; one-sided sign test p = 0.9893.
- **facts vs tuned**: facts stops fewer calls for 1 developers, more for 10, ties 2; one-sided sign test p = 0.9995.
- **ts vs tokplus**: ts stops fewer calls for 10 developers, more for 0, ties 3; one-sided sign test p = 0.0009766.
- **ts vs vocab**: ts stops fewer calls for 2 developers, more for 8, ties 3; one-sided sign test p = 0.9893.
- **ts vs tuned**: ts stops fewer calls for 0 developers, more for 11, ties 2; one-sided sign test p = 1.
- **facts vs ts**: facts stops fewer calls for 6 developers, more for 1, ties 6; one-sided sign test p = 0.0625.

## Self-published, secondary

19 developers with at least 50 shell calls

| | Agents | Shell calls | v1 | regex | tuned | vocab | facts | tok | tokplus | ts |
|---|---|---|---|---|---|---|---|---|---|---|
| **Pooled** | | 452867 | 0.27% | 1.34% | 0.58% | 0.61% | 0.73% | 0.85% | 0.84% | 0.74% |
| **Macro mean** | | | 1.04% | 2.13% | 1.44% | 1.49% | 2.26% | 1.95% | 1.88% | 2.30% |

- **facts vs tokplus**: facts stops fewer calls for 8 developers, more for 6, ties 5; one-sided sign test p = 0.3953.
- **facts vs vocab**: facts stops fewer calls for 3 developers, more for 12, ties 4; one-sided sign test p = 0.9963.
- **facts vs tuned**: facts stops fewer calls for 1 developers, more for 13, ties 5; one-sided sign test p = 0.9999.
- **ts vs tokplus**: ts stops fewer calls for 6 developers, more for 8, ties 5; one-sided sign test p = 0.788.
- **ts vs vocab**: ts stops fewer calls for 3 developers, more for 12, ties 4; one-sided sign test p = 0.9963.
- **ts vs tuned**: ts stops fewer calls for 0 developers, more for 14, ties 5; one-sided sign test p = 1.
- **facts vs ts**: facts stops fewer calls for 6 developers, more for 1, ties 12; one-sided sign test p = 0.0625.

