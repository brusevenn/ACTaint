#!/usr/bin/env python3
"""Recover ACTaint's already-paid native Sink/Taint outputs without model calls.

Read sealed experiment evidence as-is. Do not infer TP, FP, FN, or Fail.
The recovered artifact is a separate, evaluation-only output namespace.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "experiments/llm-resume-20261027/case-records.json"
SCHEMA = "ACTAINT_OFFLINE_RECOVERY_V1"
HEADER = re.compile(r"(?im)^[ \t]*--Vulnerability--[ \t]*:")
FINDING = re.compile(r"(?im)^\s*\{\s*Function\s*:\s*([^,}\n]+)")
NO_VULNERABILITY = re.compile(r"(?im)^\s*no\s+vulnerabilit(?:y|ies)\s*[.!]?\s*$")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def within_repo(relative: str) -> Path:
    target = (ROOT / relative).resolve()
    if not target.is_relative_to(ROOT.resolve()):
        raise ValueError("PATH_OUTSIDE_REPOSITORY:" + relative)
    return target


def request_stage(request: dict) -> str:
    messages = (request.get("request_body") or {}).get("messages") or []
    if not messages:
        return "UNKNOWN"
    system = str(messages[0].get("content", "")).lower()
    if "identify all **sink** operations" in system:
        return "SINK"
    if "untrusted inputs can reach any security-sensitive operations" in system:
        return "TAINT"
    return "UNKNOWN"


def extract_conclusion(output: str | None, finish_reason: str | None) -> dict:
    if output is None:
        return {"status": "MISSING_VISIBLE_OUTPUT", "functions": [], "raw_findings": []}
    if finish_reason != "stop":
        return {"status": "INCOMPLETE_RESPONSE", "functions": [], "raw_findings": []}
    headers = list(HEADER.finditer(output))
    if not headers:
        return {"status": "MISSING_MARKER", "functions": [], "raw_findings": []}
    # The last anchored header is the native final-answer boundary.
    body = output[headers[-1].end():]
    raw = [line.strip() for line in body.splitlines() if FINDING.search(line)]
    funcs = sorted({m.group(1).strip() for line in raw if (m := FINDING.search(line))})
    if raw:
        return {"status": "FINDINGS", "functions": funcs, "raw_findings": raw}
    if any(NO_VULNERABILITY.fullmatch(line.strip()) for line in body.splitlines()):
        return {"status": "EXPLICIT_NEGATIVE", "functions": [], "raw_findings": []}
    return {"status": "UNINTERPRETABLE_CONCLUSION", "functions": [], "raw_findings": []}


def read_requests(path: Path) -> dict:
    """One response per paid call ID; no retry or cherry-picking."""
    requests = {}
    responses = {}
    terminal_errors = set()
    invalid = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            obj = json.loads(line)
        except ValueError:
            invalid.append(number)
            continue
        cid = obj.get("call_id")
        if not cid:
            invalid.append(number)
            continue
        kind = obj.get("event")
        if kind == "request":
            if cid in requests:
                invalid.append(number)
            requests[cid] = obj
        elif kind == "response":
            if cid in responses:
                invalid.append(number)
            responses[cid] = obj
        elif kind == "error":
            terminal_errors.add(cid)
    entries = []
    for cid, req in requests.items():
        response = responses.get(cid)
        stage = request_stage(req)
        row = {"call_id": cid, "stage": stage, "has_response": response is not None,
               "has_error_event": cid in terminal_errors}
        if response is None:
            row.update(status="NO_RESPONSE", functions=[], raw_findings=[])
        else:
            output = response.get("visible_output")
            if output is None:
                choices = (response.get("raw_response") or {}).get("choices") or []
                if choices:
                    output = (choices[0].get("message") or {}).get("content")
            row.update(extract_conclusion(output, response.get("finish_reason")) if stage == "TAINT"
                       else {"status": "STAGE_RESPONSE", "functions": [], "raw_findings": []})
            row.update(visible_output=output, finish_reason=response.get("finish_reason"),
                       response_complete=response.get("response_complete") is True)
        entries.append(row)
    return {"request_log_sha256": sha(path), "invalid_lines": invalid,
            "orphan_response_call_ids": sorted(set(responses) - set(requests)),
            "entries": entries}


def recover_project(project_id: str, artifact: str | None) -> dict:
    if artifact is None:
        return {"project_id": project_id, "source_artifact": None,
                "status": "SOURCE_ARTIFACT_MISSING", "files": []}
    root = within_repo(artifact)
    native = root / "native"
    native_result = native / "project-result.json"
    if not native_result.is_file():
        return {"project_id": project_id, "source_artifact": artifact,
                "status": "NATIVE_RESULT_MISSING", "files": []}
    result = json.loads(native_result.read_text(encoding="utf-8"))
    if result.get("project_id") != project_id:
        raise ValueError("PROJECT_ID_MISMATCH:" + project_id)
    records = []
    for f in result.get("file_results", []):
        row = {"source_path": f.get("source_repo_path") or f.get("tool_input_path"),
               "source_sha256": f.get("source_sha256"),
               "original_file_status": f.get("status"),
               "original_exit_code": f.get("exit_code"),
               "original_analyzer_summary": f.get("analyzer_summary"),
               "request_log_path": f.get("request_log_path")}
        raw_path = f.get("request_log_path")
        if raw_path:
            log = (native / raw_path).resolve()
            if not log.is_relative_to(native.resolve()):
                raise ValueError("REQUEST_LOG_OUTSIDE_NATIVE:" + str(raw_path))
            if log.is_file():
                row["request_evidence"] = read_requests(log)
            else:
                row["request_evidence"] = {"status": "REQUEST_LOG_MISSING"}
        else:
            row["request_evidence"] = {"status": "NO_REQUEST_LOG"}
        records.append(row)
    return {"project_id": project_id, "source_artifact": artifact,
            "original_project_status": result.get("status"),
            "original_project_result_sha256": sha(native_result),
            "status": "RECOVERED", "files": records}


def recover(input_path: Path, output: Path) -> dict:
    source = json.loads(input_path.read_text(encoding="utf-8"))
    cases = source.get("records", [])
    if len(cases) != 154 or len({c["case_id"] for c in cases}) != 154:
        raise ValueError("EXPECTED_154_UNIQUE_CASE_IDS")
    projects = {}
    for case in cases:
        pid = case["project_id"]
        ref = case.get("execution_artifact")
        if pid in projects and projects[pid] != ref:
            raise ValueError("CONFLICTING_PROJECT_EVIDENCE:" + pid)
        projects[pid] = ref
    if len(projects) != 121:
        raise ValueError("EXPECTED_121_PROJECTS")
    output = output.resolve()
    # Recovery must never overwrite a historical run or raw evidence.
    historical = (ROOT / "experiments").resolve()
    protected = [historical / name for name in (
        "llm-resume-20261027",
        "comparison-20261027-deepseek-high",
        "cache-optimization-20261027",
    )]
    if output == historical or any(output == path or path in output.parents for path in protected):
        raise ValueError("HISTORICAL_EVIDENCE_OUTPUT_FORBIDDEN")
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("RECOVERY_OUTPUT_MUST_BE_EMPTY:" + str(output))
    output.mkdir(parents=True, exist_ok=True)
    project_dir = output / "projects"
    project_dir.mkdir()
    status = Counter()
    for pid, artifact in sorted(projects.items()):
        report = recover_project(pid, artifact)
        for f in report["files"]:
            ev = f.get("request_evidence") or {}
            for entry in ev.get("entries", []):
                if entry.get("stage") == "TAINT":
                    status[entry["status"]] += 1
        status["PROJECT_" + report["status"]] += 1
        (project_dir / (pid + ".json")).write_text(
            json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8")
    catalog = {
        "schema": SCHEMA, "tool": "ACTaint", "dataset": "ACToolBench154",
        "case_count": len(cases), "project_count": len(projects),
        "source_case_records_sha256": sha(input_path),
        "scoring_performed": False, "llm_requests_performed": 0,
        "counts": dict(sorted(status.items())),
        "cases": [{"case_id": x["case_id"], "project_id": x["project_id"],
                   "project_report": "projects/" + x["project_id"] + ".json",
                   "source_execution_artifact": x.get("execution_artifact"),
                   "original_case_status": x.get("status")} for x in cases]
    }
    (output / "recovery-manifest.json").write_text(
        json.dumps(catalog, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8")
    return catalog


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-records", type=Path, default=INPUT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = recover(args.case_records, args.output)
    print(json.dumps({"cases": summary["case_count"], "projects": summary["project_count"],
                      "counts": summary["counts"], "scoring_performed": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
