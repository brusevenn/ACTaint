# ACToolBench154 continuation run

This directory is the independent continuation namespace; historical sealed results are untouched. It accounts for all 154 case IDs grouped into 121 unique project source trees. Inputs are the label-free tool index and source manifest; evaluation labels were not loaded.

The resume plan records every case and project disposition. Only project groups with no prior model request are eligible for a new request. Previously paid/requested groups and completed or cache-diagnostic groups are referenced, not replayed. Each eligible project is run once. There are zero automatic retries. A provider authentication/payment error halts the current project and the remaining queue; pending items are explicitly marked not run.

Protocol: deepseek-flash, high reasoning, thinking enabled, max output 65,536 tokens, 300-second request timeout, 1,200-second project timeout, total concurrency 3 for this synchronized phase (GPTLens 2 + ACTaint 1); no temperature/top_p overrides. Prompt layout is prefix_stable_v2; cache-hit rate is not a gate for this continuation.

The job folders retain native tool outputs, request/response/error logs, stdout/stderr, and per-project receipts. case-records.json, execution-summary.json, and resume-seal.json are written after the queue terminates. No vulnerability scoring is performed in the detector run.
\nThe code_sha field identifies the latest commit that changed the execution scripts; later commits that only add plans, logs, or results do not change the runner identity.\n\nACTaint uses one project worker while running alongside GPTLens (two workers), so the temporary combined concurrency ceiling is 3.\n

## Path privacy normalization

To avoid publishing machine-specific absolute paths, runtime-only local paths in saved output files were replaced with explicit placeholders. Exact before/after SHA-256 values and replacement rules are recorded in path-normalization.json; original changed files and the preceding seal were preserved outside this repository on the execution host. This changes only path strings, not detector inputs, model outputs, case dispositions, or request counts. The new resume seal binds the normalized output set and references the prior seal.
