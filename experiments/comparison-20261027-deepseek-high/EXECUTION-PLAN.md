# Authorized three-tool comparison execution
## Scope (never run CADG/R3)
ACTaint/main: ACToolBench154. GPTLens/release: ACToolBench154.
ASTRO/main: ACToolBench154 + SmartBugsWild533. Total995 tool-case records.
Native execution runs on Ubuntu22.04 over SSH only.
The smart-contract-AC-detector repository is READ-ONLY as a dataset source.
## Inputs / denominator
ACToolBench154 maps to121 unique source projects and694 .sol files.
Per-tool project jobs process the complete indexed native file set once and fan out project outputs to all associated case IDs. Neither694 files nor121 projects replaces the154-case denominator.
A1200-second wall-time deadline covers all native stages/files of a project job (one source universe reused by cases). Unstarted files get NOT_RUN_CASE_TIMEOUT; failures are not negatives.
ASTRO SmartBugs has533 neutral sources/records. Labels/evaluation metadata are NEVER sent to tools/model.
## LLM protocol
deepseek-flash; reasoning_effort=high; thinking enabled; max_tokens65536;
request timeout300s; SDK and application retry0; GLOBAL concurrency2; direct trust_env=False.
No temperature/top_p. No key/.env/private paths in committed artifacts.
Cache token rate=sum(cache_hit_tokens)/sum(prompt_tokens), not request count.
Diagnose independently for ACTaint and GPTLens, at most3 rounds using distinct project/source IDs. Use authentic native requests, never padding or duplicate samples.
Round1 baseline, round2 semantically equivalent stable instruction prefix, round3 grouping/order if needed. If95% cannot be established, preserve real statistics and reason and continue authorized full run.
Diagnostic project outputs count toward formal coverage and are reused, never re-requested in the full run. Changed prompt layout is versioned per request/output and reported as diagnostic/formal strata.
## Native tool boundaries
ACTaint: native static analysis and taint/sink agents, no CADG/source-only replacement.
GPTLens: native auditor->few-shot critic->default ranker; no replacement detector.
ASTRO: native graph->similarity/matching against fixed existing audited-reference source; reference coverage limitation explicit. No tested-source/labels used as reference. A missing/failed reference is an error, never negative.
## Deliverables / review gates
1. Preserve existing dirty changes; add and test tool-specific isolated per-project harnesses.
2. Verify every input byte/hash/count; install/verify official compiler binaries where possible.
3. Independent read-only reviewer checks scope, model params, no retries/leaks, timeout/errors/mapping.
4. Commit/push implementation/tests to each own existing branch using fast-forward; record code SHA.
5. Run unique diagnostic rounds then remaining jobs. Save every response incl reasoning, requests, stdout/stderr, error, timeout, usage and source/config identity. No accuracy scoring.
6. Seal per-tool full995 record accounting, file hashes, cache diagnosis/report and raw outputs.
7. Commit/push results to each own repo independent result directory; remote readback path/count/hash verification.
No result/implementation files written into smart-contract-AC-detector.
