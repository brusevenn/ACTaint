# ACToolBench154 continuation run

This directory is the independent continuation namespace; historical sealed results are untouched. It accounts for all 154 case IDs grouped into 121 unique project source trees. Inputs are the label-free tool index and source manifest; evaluation labels were not loaded.

The resume plan records every case and project disposition. Only project groups with no prior model request are eligible for a new request. Previously paid/requested groups and completed or cache-diagnostic groups are referenced, not replayed. Each eligible project is run once. There are zero automatic retries. A provider authentication/payment error halts the current project and the remaining queue; pending items are explicitly marked not run.

Protocol: deepseek-flash, high reasoning, thinking enabled, max output 65,536 tokens, 300-second request timeout, 1,200-second project timeout, concurrency 2, no temperature/top_p overrides. Prompt layout is prefix_stable_v2; cache-hit rate is not a gate for this continuation.

The job folders retain native tool outputs, request/response/error logs, stdout/stderr, and per-project receipts. case-records.json, execution-summary.json, and resume-seal.json are written after the queue terminates. No vulnerability scoring is performed in the detector run.
