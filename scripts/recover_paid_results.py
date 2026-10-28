#!/usr/bin/env python3
"""Recover ACTaint's already-paid native Sink/Taint outputs without model calls.

Read sealed experiment evidence as-is. Do not infer TP, FP, FN, or Fail.
The recovered artifact is a separate, evaluation-only output namespace.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "experiments/llm-resume-20261027/case-records.json"
INPUT_INDEX = ROOT / "datasets/actoolbench-cleaned-154/tools/actaint/input-index.json"
DATASET_ROOT = ROOT / "datasets/actoolbench-cleaned-154/full"
SCHEMA = "ACTAINT_OFFLINE_RECOVERY_V2"
SOURCE_RUN_SPECS = {
    "comparison-20261027-deepseek-high": {
        "seal_path": "actoolbench154/predictions-seal.json",
        "inventory_root": "actoolbench154",
        "self_hash": True,
    },
    "cache-optimization-20261027": {
        "seal_path": "diagnostic-seal.json",
        "inventory_root": ".",
        "self_hash": False,
    },
    "llm-resume-20261027": {
        "seal_path": "resume-seal.json",
        "inventory_root": ".",
        "self_hash": True,
    },
}
FORBIDDEN_LABEL_KEYS = {
    "label", "labels", "ground_truth", "ground_truth_status", "root_cause",
    "vulnerability_type", "vulnerable_function", "adjudication", "reference_label",
}
HEADER = re.compile(r"(?im)^[ \t]*--Vulnerability--[ \t]*:")
FINDING = re.compile(r"(?im)^\s*\{\s*Function\s*:\s*(.+?)(?=,\s*(?:Taint\s+Path|Description)\s*:|\}\s*$)")
NO_VULNERABILITY = re.compile(r"(?im)^\s*no\s+vulnerabilit(?:y|ies)\s*[.!]?\s*$")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(value: dict) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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


def extract_conclusion(
    output: str | None,
    finish_reason: str | None,
    response_complete: bool | None,
) -> dict:
    empty = {"functions": [], "raw_findings": [], "format_warnings": []}
    if output is None:
        return {**empty, "status": "MISSING_VISIBLE_OUTPUT"}
    if response_complete is False:
        return {**empty, "status": "INCOMPLETE_RESPONSE"}
    if response_complete is not True:
        return {**empty, "status": "COMPLETENESS_UNVERIFIED"}
    if finish_reason != "stop":
        return {**empty, "status": "INCOMPLETE_RESPONSE"}
    headers = list(HEADER.finditer(output))
    if not headers:
        return {**empty, "status": "MISSING_MARKER"}
    # The last anchored header is the native final-answer boundary.
    body = output[headers[-1].end():]
    raw = [line.strip() for line in body.splitlines() if FINDING.search(line)]
    funcs = sorted({m.group(1).strip() for line in raw if (m := FINDING.search(line))})
    warnings = []
    for line in raw:
        if not re.search(r"(?i),\s*Description\s*:", line):
            warnings.append("MISSING_DESCRIPTION_FIELD")
        if len(re.findall(r"(?i),\s*Taint\s+Path\s*:", line)) > 1:
            warnings.append("DUPLICATE_TAINT_PATH_FIELD")
    if raw:
        return {"status": "FINDINGS", "functions": funcs, "raw_findings": raw,
                "format_warnings": sorted(set(warnings))}
    if any(NO_VULNERABILITY.fullmatch(line.strip()) for line in body.splitlines()):
        return {"status": "EXPLICIT_NEGATIVE", "functions": [], "raw_findings": [],
                "format_warnings": []}
    return {**empty, "status": "UNINTERPRETABLE_CONCLUSION"}

def read_requests(path: Path) -> dict:
    """Keep complete per-call request/response/error events, linked only by call_id."""
    requests = defaultdict(list)
    responses = defaultdict(list)
    errors = defaultdict(list)
    unknown = []
    invalid = []
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        try:
            obj = json.loads(line)
        except ValueError:
            invalid.append({"line_number": number, "raw_line_sha256": hashlib.sha256(
                line.encode("utf-8")).hexdigest()})
            continue
        cid = obj.get("call_id")
        if not cid:
            invalid.append({"line_number": number, "raw_event": sanitize_strings(obj)})
            continue
        event = {"line_number": number, "raw_event": sanitize_strings(obj)}
        kind = obj.get("event")
        if kind == "request":
            requests[cid].append(event)
        elif kind == "response":
            responses[cid].append(event)
        elif kind == "error":
            errors[cid].append(event)
        else:
            unknown.append(event)
    entries = []
    for cid, request_events in requests.items():
        response_events = responses.get(cid, [])
        error_events = errors.get(cid, [])
        req = request_events[0]["raw_event"]
        response_item = response_events[0]["raw_event"] if len(response_events) == 1 else None
        stage = request_stage(req)
        row = {
            "call_id": cid,
            "stage": stage,
            "request_line_numbers": [x["line_number"] for x in request_events],
            "response_line_numbers": [x["line_number"] for x in response_events],
            "error_line_numbers": [x["line_number"] for x in error_events],
            "request_event": req if len(request_events) == 1 else None,
            "request_events": [x["raw_event"] for x in request_events],
            "response_event": response_item,
            "response_events": [x["raw_event"] for x in response_events],
            "error_events": [x["raw_event"] for x in error_events],
            "has_response": bool(response_events),
            "has_error_event": bool(error_events),
            "functions": [],
            "raw_findings": [],
        }
        if len(request_events) > 1:
            row["status"] = "DUPLICATE_REQUEST_EVENTS"
        elif len(response_events) > 1:
            row["status"] = "DUPLICATE_RESPONSE_EVENTS"
        elif not response_events:
            row["status"] = "NO_RESPONSE"
        else:
            output = response_item.get("visible_output")
            if output is None:
                choices = (response_item.get("raw_response") or {}).get("choices") or []
                if choices:
                    output = (choices[0].get("message") or {}).get("content")
            if stage == "TAINT":
                row.update(extract_conclusion(
                    output, response_item.get("finish_reason"),
                    response_item.get("response_complete")))
            elif stage == "SINK":
                complete = response_item.get("response_complete")
                finish_reason = response_item.get("finish_reason")
                if complete is False or finish_reason != "stop":
                    row["status"] = "INCOMPLETE_RESPONSE"
                elif complete is not True:
                    row["status"] = "COMPLETENESS_UNVERIFIED"
                else:
                    row["status"] = "STAGE_RESPONSE"
            else:
                row["status"] = "UNKNOWN_STAGE_RESPONSE"
            row.update(
                visible_output=output,
                finish_reason=response_item.get("finish_reason"),
                response_complete=response_item.get("response_complete"),
                response_metadata={
                    key: value for key, value in response_item.items()
                    if key not in ("event", "call_id", "visible_output", "raw_response")
                },
            )
        entries.append(row)
    return {
        "request_log_sha256": sha(path),
        "invalid_lines": invalid,
        "unknown_event_lines": unknown,
        "orphan_response_call_ids": sorted(set(responses) - set(requests)),
        "orphan_response_events": [
            item["raw_event"] for cid in sorted(set(responses) - set(requests))
            for item in responses[cid]
        ],
        "orphan_error_call_ids": sorted(set(errors) - set(requests)),
        "orphan_error_events": [
            item["raw_event"] for cid in sorted(set(errors) - set(requests))
            for item in errors[cid]
        ],
        "entries": entries,
    }

def _reject_label_fields(value: object, scope: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN_LABEL_KEYS:
                raise ValueError("LABEL_FIELD_IN_RECOVERY_INPUT:" + scope + ":" + str(key))
            _reject_label_fields(child, scope)
    elif isinstance(value, list):
        for child in value:
            _reject_label_fields(child, scope)


def _normalized_config_path(value: str) -> str:
    prefix = "datasets/actoolbench-cleaned-154/full/"
    return value.removeprefix(prefix)


def validate_input_records(input_path: Path, index_path: Path) -> dict:
    input_path = input_path.resolve()
    index_path = index_path.resolve()
    if not input_path.is_relative_to(ROOT.resolve()) or not index_path.is_relative_to(ROOT.resolve()):
        raise ValueError("RECOVERY_INPUT_OUTSIDE_REPOSITORY")
    source = json.loads(input_path.read_text(encoding="utf-8"))
    index = json.loads(index_path.read_text(encoding="utf-8"))
    _reject_label_fields(source, "case_records")
    _reject_label_fields(index, "input_index")
    cases = source.get("records", [])
    index_cases = index.get("cases", [])
    index_projects = index.get("projects", [])
    index_files = index.get("files", [])
    if index.get("case_labels_included") is not False:
        raise ValueError("INPUT_INDEX_MUST_EXCLUDE_LABELS")
    if (len(cases), len({x.get("case_id") for x in cases})) != (154, 154):
        raise ValueError("EXPECTED_154_UNIQUE_CASE_IDS")
    if (len(index_cases), len({x.get("case_id") for x in index_cases})) != (154, 154):
        raise ValueError("INPUT_INDEX_EXPECTED_154_UNIQUE_CASE_IDS")
    if len(index_projects) != 121 or len({x.get("project_id") for x in index_projects}) != 121:
        raise ValueError("INPUT_INDEX_EXPECTED_121_PROJECTS")
    if len(index_files) != 694 or len({x.get("tool_input_path") for x in index_files}) != 694:
        raise ValueError("INPUT_INDEX_EXPECTED_694_SOURCE_FILES")
    case_by_id = {x["case_id"]: x for x in index_cases}
    if {x["case_id"] for x in cases} != set(case_by_id):
        raise ValueError("CASE_IDS_DO_NOT_MATCH_LABEL_FREE_INPUT_INDEX")
    project_index = {x["project_id"]: x for x in index_projects}
    case_rows_by_project = defaultdict(list)
    files_by_project = defaultdict(dict)
    for row in index_files:
        pid = row["project_id"]
        rel = row["tool_input_path"]
        if rel in files_by_project[pid]:
            raise ValueError("DUPLICATE_PROJECT_INPUT_PATH:" + pid + ":" + rel)
        source_path = within_repo(row["source_path"])
        tool_path = within_repo((DATASET_ROOT / rel).relative_to(ROOT).as_posix())
        expected = row["sha256"]
        if not source_path.is_file() or not tool_path.is_file():
            raise ValueError("SOURCE_FILE_MISSING:" + pid + ":" + rel)
        if sha(source_path) != expected or sha(tool_path) != expected:
            raise ValueError("SOURCE_FILE_HASH_MISMATCH:" + pid + ":" + rel)
        if row.get("bytes") is not None and tool_path.stat().st_size != row["bytes"]:
            raise ValueError("SOURCE_FILE_SIZE_MISMATCH:" + pid + ":" + rel)
        files_by_project[pid][rel] = row
    for row in index_cases:
        pid = row["project_id"]
        case_rows_by_project[pid].append(row)
    record_by_project = defaultdict(list)
    for row in cases:
        case_id = row["case_id"]
        idx_case = case_by_id[case_id]
        pid = idx_case["project_id"]
        if row.get("project_id") != pid:
            raise ValueError("CASE_PROJECT_MAPPING_MISMATCH:" + case_id)
        record_by_project[pid].append(row)
    config_hashes = {}
    for pid in sorted(project_index):
        pindex = project_index[pid]
        input_case_rows = case_rows_by_project[pid]
        record_rows = record_by_project[pid]
        if len(input_case_rows) != pindex.get("case_count"):
            raise ValueError("PROJECT_CASE_COUNT_MISMATCH:" + pid)
        if len(record_rows) != len(input_case_rows):
            raise ValueError("PROJECT_CASE_RECORD_COUNT_MISMATCH:" + pid)
        project_files = files_by_project[pid]
        if len(project_files) != pindex.get("source_file_count"):
            raise ValueError("PROJECT_SOURCE_FILE_COUNT_MISMATCH:" + pid)
        expected_inventory = sorted([
            [row.get("source_relative_path") or Path(row["source_path"]).name, row["sha256"]]
            for row in project_files.values()
        ])
        expected_hashes = sorted({row["sha256"] for row in project_files.values()})
        expected_configs = sorted({_normalized_config_path(x) for x in pindex.get("compile_config_paths", [])})
        if len(expected_configs) != 1:
            raise ValueError("EXPECTED_ONE_PROJECT_COMPILE_CONFIG:" + pid)
        config_path = within_repo(pindex["compile_config_paths"][0])
        if not config_path.is_file():
            raise ValueError("COMPILE_CONFIG_MISSING:" + pid)
        config_hash = sha(config_path)
        config_hashes[pid] = config_hash
        for row in record_rows:
            if sorted(row.get("source_file_inventory", [])) != expected_inventory:
                raise ValueError("CASE_SOURCE_INVENTORY_MISMATCH:" + row["case_id"])
            if sorted(row.get("source_hashes", [])) != expected_hashes:
                raise ValueError("CASE_SOURCE_HASH_SET_MISMATCH:" + row["case_id"])
            actual_configs = sorted({_normalized_config_path(x) for x in row.get("compile_config_paths", [])})
            if actual_configs != expected_configs:
                raise ValueError("CASE_COMPILE_CONFIG_MAPPING_MISMATCH:" + row["case_id"])
            if row.get("compile_config_sha256") != config_hash:
                raise ValueError("CASE_COMPILE_CONFIG_HASH_MISMATCH:" + row["case_id"])
    return {
        "source": source,
        "index": index,
        "cases": cases,
        "project_index": project_index,
        "case_ids_by_project": {
            pid: sorted(row["case_id"] for row in rows)
            for pid, rows in case_rows_by_project.items()
        },
        "files_by_project": files_by_project,
        "validation": {
            "case_count": len(cases),
            "project_count": len(project_index),
            "source_file_count": len(index_files),
            "case_ids_exact_match": True,
            "case_project_mappings_validated": True,
            "source_paths_and_sha256_validated": True,
            "compile_config_paths_and_sha256_validated": True,
            "case_labels_included": False,
        },
    }


def _source_seal(run_name: str) -> dict:
    spec = SOURCE_RUN_SPECS[run_name]
    run_root = within_repo("experiments/" + run_name)
    seal_path = within_repo((run_root / spec["seal_path"]).relative_to(ROOT).as_posix())
    inventory_root = run_root if spec["inventory_root"] == "." else within_repo(
        (run_root / spec["inventory_root"]).relative_to(ROOT).as_posix()
    )
    seal_obj = json.loads(seal_path.read_text(encoding="utf-8"))
    inventory = seal_obj.get("files")
    if not isinstance(inventory, dict):
        raise ValueError("SOURCE_SEAL_FILE_INVENTORY_MISSING:" + run_name)
    actual = {
        path.relative_to(inventory_root).as_posix()
        for path in inventory_root.rglob("*")
        if path.is_file() and path.resolve() != seal_path.resolve()
    }
    if set(inventory) != actual:
        raise ValueError("SOURCE_SEAL_FILE_SET_MISMATCH:" + run_name)
    for relative, expected_hash in inventory.items():
        path = (inventory_root / relative).resolve()
        if not path.is_relative_to(inventory_root.resolve()) or sha(path) != expected_hash:
            raise ValueError("SOURCE_SEAL_HASH_MISMATCH:" + run_name + ":" + relative)
    seal_hash = seal_obj.get("seal_sha256")
    if seal_hash and canonical_sha256({k: v for k, v in seal_obj.items() if k != "seal_sha256"}) != seal_hash:
        raise ValueError("SOURCE_SEAL_SELF_HASH_MISMATCH:" + run_name)
    return {
        "run_name": run_name,
        "seal_source_path": (Path("experiments") / run_name / spec["seal_path"]).as_posix(),
        "seal_sha256": sha(seal_path),
        "seal_self_hash": seal_hash,
        "sealed_file_count": len(inventory),
        "inventory_exact": True,
    }


def _normalize_snapshot_bytes(data: bytes) -> tuple[bytes, list[str]]:
    replacements = [
        (str(ROOT).rstrip("/") + "/", b"$ACTAINT_REPO/", "ACTAINT_REPO"),
        (str(ROOT.parent / "comparison-runs").rstrip("/") + "/", b"$COMPARISON_RUNS/", "COMPARISON_RUNS"),
        (str(ROOT.parent).rstrip("/") + "/", b"$SHANZY_ROOT/", "SHANZY_ROOT"),
        (str(Path.home()).rstrip("/") + "/", b"$HOME/", "HOME"),
    ]
    result = data
    tokens = []
    for prefix, replacement, name in replacements:
        if prefix.encode() in result:
            result = result.replace(prefix.encode(), replacement)
            tokens.append(name)
    return result, tokens



def evidence_snapshot_path(artifact: str, suffix: Path = Path()) -> Path:
    parts = Path(artifact).parts
    if len(parts) < 3 or parts[0] != "experiments" or parts[1] not in SOURCE_RUN_SPECS:
        raise ValueError("UNSUPPORTED_SOURCE_ARTIFACT:" + artifact)
    return Path("evidence/source-runs") / parts[1] / Path(*parts[2:]) / suffix


def sanitize_strings(value: object) -> object:
    if isinstance(value, str):
        raw, _tokens = _normalize_snapshot_bytes(value.encode("utf-8"))
        return raw.decode("utf-8")
    if isinstance(value, list):
        return [sanitize_strings(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_strings(item) for key, item in value.items()}
    return value


def snapshot_source_runs(output: Path) -> dict:
    evidence_root = output / "evidence" / "source-runs"
    evidence_root.mkdir(parents=True, exist_ok=True)
    source_runs = []
    files = []
    for run_name in SOURCE_RUN_SPECS:
        source_root = within_repo("experiments/" + run_name)
        seal_info = _source_seal(run_name)
        dest_root = evidence_root / run_name
        dest_root.mkdir(parents=True, exist_ok=False)
        for source in sorted(source_root.rglob("*")):
            if source.is_symlink():
                raise ValueError("SYMLINK_IN_SOURCE_EVIDENCE:" + source.relative_to(ROOT).as_posix())
            if not source.is_file():
                continue
            relative = source.relative_to(source_root)
            destination = dest_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            original_hash = sha(source)
            raw = source.read_bytes()
            snapshot_bytes, normalized_tokens = _normalize_snapshot_bytes(raw)
            temp = destination.with_name(destination.name + ".copy-tmp")
            temp.write_bytes(snapshot_bytes)
            shutil.copystat(source, temp)
            os.replace(temp, destination)
            copied_hash = sha(destination)
            if sha(source) != original_hash:
                raise ValueError("SOURCE_CHANGED_DURING_SNAPSHOT:" + source.relative_to(ROOT).as_posix())
            files.append({
                "source_path": (Path("experiments") / run_name / relative).as_posix(),
                "snapshot_path": (Path("evidence/source-runs") / run_name / relative).as_posix(),
                "original_sha256": original_hash,
                "snapshot_sha256": copied_hash,
                "bytes": len(raw),
                "path_normalized": bool(normalized_tokens),
                "normalization_tokens": normalized_tokens,
            })
        source_runs.append(seal_info)
    return {
        "schema": "ACTAINT_SOURCE_EVIDENCE_MANIFEST_V1",
        "source_roots": source_runs,
        "file_count": len(files),
        "files": files,
        "original_roots_modified": False,
    }


def _native_file_evidence(artifact: str, tool_input_path: str) -> dict:
    file_key = hashlib.sha256(tool_input_path.encode("utf-8")).hexdigest()[:16]
    result = {}
    for name in ("status.json", "stdout.txt", "stderr.txt"):
        rel = Path("native") / "files" / file_key / name
        path = within_repo((Path(artifact) / rel).as_posix())
        if path.is_file():
            result[name] = {
                "source_path": (Path(artifact) / rel).as_posix(),
                "snapshot_path": evidence_snapshot_path(artifact, rel).as_posix(),
                "sha256": sha(path),
                "bytes": path.stat().st_size,
            }
    return result


def _classify_sink_evidence(entries: list[dict]) -> str:
    sink_entries = [entry for entry in entries if entry.get("stage") == "SINK"]
    if not sink_entries:
        return "SINK_RESPONSE_NOT_AVAILABLE"
    complete = [
        entry for entry in sink_entries
        if entry.get("status") == "STAGE_RESPONSE"
        and entry.get("response_complete") is True
        and entry.get("finish_reason") == "stop"
    ]
    if len(complete) != len(sink_entries):
        return "SINK_RESPONSE_MISSING_OR_INCOMPLETE"
    explicit_no_sinks = re.compile(r"(?im)^\s*no\s+sinks?\s*[.!]?\s*$")
    if all(any(explicit_no_sinks.fullmatch(line.strip())
               for line in (entry.get("visible_output") or "").splitlines())
           for entry in complete):
        return "SINK_STAGE_EXPLICIT_NO_SINKS"
    return "SINK_STAGE_RESPONSE_WITHOUT_EXPLICIT_NO_SINKS"

def _native_gap_reason(file_result: dict, evidence: dict, sink_class: str) -> tuple[str, str]:
    status = file_result.get("status")
    summary = file_result.get("analyzer_summary")
    if status == "ERROR" and sink_class != "SINK_RESPONSE_NOT_AVAILABLE":
        return "ORIGINAL_TOOL_ERROR_AFTER_SINK_STAGE", (
            "Original native file status is ERROR after Sink-stage evidence; exact stdout/stderr and request log are linked."
        )
    if status == "ERROR":
        return "ORIGINAL_TOOL_ERROR_BEFORE_MODEL_REQUEST", (
            "Original native file status is ERROR with no request evidence; exact saved stdout/stderr are linked."
        )
    if isinstance(summary, dict):
        if summary.get("contracts_skipped_interface_abstract_library", 0) and not summary.get("contracts_analyzed", 0):
            return "NATIVE_ANALYZER_SKIPPED_NON_IMPLEMENTABLE_CONTRACTS", (
                "Original analyzer summary records interface/abstract/library skips and no analyzed contract."
            )
        if summary.get("contracts_without_native_candidates", 0):
            return "NATIVE_ANALYZER_REPORTED_NO_NATIVE_CANDIDATE", (
                "Original analyzer summary records contracts_without_native_candidates."
            )
        if not summary.get("contracts_analyzed", 0):
            return "NATIVE_ANALYZER_REPORTED_NO_ANALYZED_CONTRACT", (
                "Original analyzer summary records zero analyzed contracts."
            )
    if sink_class == "SINK_STAGE_EXPLICIT_NO_SINKS":
        return "NO_TAINT_STAGE_AFTER_EXPLICIT_NO_SINKS", (
            "Complete saved Sink response explicitly says no sinks; no Taint request event is present."
        )
    if status == "COMPLETED" and not file_result.get("request_log_path"):
        return "NATIVE_PIPELINE_COMPLETED_WITHOUT_MODEL_REQUEST", (
            "Original native status is COMPLETED and no request-log path was recorded."
        )
    if evidence:
        return "NO_TAINT_STAGE_AFTER_SINK_RESPONSE", (
            "The saved request log has Sink evidence but no Taint request; consult original file outputs."
        )
    return "NO_MODEL_REQUEST_EVIDENCE", (
        "No request-log path or native skip summary explains the absence; source outputs are preserved for audit."
    )

def validate_project_artifact(
    project_id: str,
    artifact: str,
    project_case_ids: list[str],
    project_files: dict,
) -> tuple[dict, dict]:
    root = within_repo(artifact)
    native = root / "native"
    native_result = native / "project-result.json"
    if not native_result.is_file():
        return {
            "project_id": project_id,
            "case_ids": sorted(project_case_ids),
            "source_artifact": artifact,
            "evidence_artifact_path": evidence_snapshot_path(artifact).as_posix(),
            "status": "NATIVE_RESULT_MISSING",
            "files": [],
        }, {}
    result = json.loads(native_result.read_text(encoding="utf-8"))
    if result.get("project_id") != project_id:
        raise ValueError("PROJECT_ID_MISMATCH:" + project_id)
    if set(result.get("case_ids", [])) != set(project_case_ids):
        raise ValueError("NATIVE_CASE_ID_MAPPING_MISMATCH:" + project_id)
    native_files = result.get("file_results", [])
    native_paths = [f.get("tool_input_path") for f in native_files]
    if len(native_paths) != len(set(native_paths)) or set(native_paths) != set(project_files):
        raise ValueError("NATIVE_SOURCE_FILE_SET_MISMATCH:" + project_id)

    records = []
    stage_totals = Counter()
    for f in native_files:
        tool_path = f.get("tool_input_path")
        expected = project_files[tool_path]
        if f.get("source_sha256") != expected.get("sha256") or f.get("actual_source_sha256") != expected.get("sha256"):
            raise ValueError("NATIVE_SOURCE_HASH_MISMATCH:" + project_id + ":" + str(tool_path))
        if f.get("source_repo_path") != expected.get("source_path"):
            raise ValueError("NATIVE_SOURCE_PATH_MISMATCH:" + project_id + ":" + str(tool_path))

        evidence_files = _native_file_evidence(artifact, tool_path)
        row = {
            "source_path": f.get("source_repo_path"),
            "tool_input_path": tool_path,
            "source_sha256": f.get("source_sha256"),
            "source_mapping_validated": True,
            "original_file_status": f.get("status"),
            "original_exit_code": f.get("exit_code"),
            "original_error_type": f.get("error_type"),
            "original_analyzer_summary": f.get("analyzer_summary"),
            "original_file_evidence": evidence_files,
            "request_log_path": f.get("request_log_path"),
            "missing_stages": [],
        }
        raw_path = f.get("request_log_path")
        if not raw_path:
            row["request_evidence"] = {"status": "NO_REQUEST_LOG"}
            row["missing_stages"] = ["SINK", "TAINT"]
            reason_code, reason = _native_gap_reason(f, {}, "SINK_RESPONSE_NOT_AVAILABLE")
            row.update(recovery_status="NO_MODEL_CALL_EVIDENCE",
                       stage_gap_reason={"code": reason_code, "explanation": reason})
        else:
            log = (native / raw_path).resolve()
            if not log.is_relative_to(native.resolve()):
                raise ValueError("REQUEST_LOG_OUTSIDE_NATIVE:" + str(raw_path))
            if not log.is_file():
                row["request_evidence"] = {"status": "REQUEST_LOG_MISSING"}
                row["missing_stages"] = ["SINK", "TAINT"]
                row.update(
                    recovery_status="REQUEST_LOG_MISSING",
                    stage_gap_reason={
                        "code": "REQUEST_LOG_MISSING",
                        "explanation": "Native result references a request log that is absent; saved stdout/stderr remain linked.",
                    },
                )
            else:
                request_evidence = read_requests(log)
                request_evidence["source_log_path"] = (Path(artifact) / "native" / raw_path).as_posix()
                request_evidence["source_log_copy_path"] = evidence_snapshot_path(
                    artifact, Path("native") / raw_path
                ).as_posix()
                for entry in request_evidence.get("entries", []):
                    for request_event in entry.get("request_events", []):
                        if request_event.get("project_id") not in (None, project_id):
                            raise ValueError("REQUEST_PROJECT_ID_MISMATCH:" + project_id)
                        if request_event.get("source_file") not in (tool_path, expected.get("source_path")):
                            raise ValueError("REQUEST_SOURCE_PATH_MISMATCH:" + project_id + ":" + str(tool_path))
                        call_case_ids = request_event.get("case_ids")
                        if call_case_ids and set(call_case_ids) != set(project_case_ids):
                            raise ValueError("REQUEST_CASE_IDS_MISMATCH:" + project_id)
                        call_case_id = request_event.get("case_id")
                        if call_case_id and call_case_id not in set(project_case_ids):
                            raise ValueError("REQUEST_CASE_ID_MISMATCH:" + project_id)
                    stage_totals[entry.get("stage", "UNKNOWN")] += 1

                entries = request_evidence.get("entries", [])
                sink_calls = [x for x in entries if x.get("stage") == "SINK"]
                taint_calls = [x for x in entries if x.get("stage") == "TAINT"]
                sink_class = _classify_sink_evidence(entries)
                row["sink_stage_evidence_status"] = sink_class
                if not sink_calls:
                    row["missing_stages"].append("SINK")
                elif any(x.get("status") != "STAGE_RESPONSE" for x in sink_calls):
                    row["missing_stages"].append("SINK_COMPLETE_RESPONSE")

                if not taint_calls:
                    row["missing_stages"].append("TAINT")
                    reason_code, reason = _native_gap_reason(f, entries, sink_class)
                    row["recovery_status"] = (
                        "NO_TAINT_REQUEST_AFTER_EXPLICIT_NO_SINKS"
                        if sink_class == "SINK_STAGE_EXPLICIT_NO_SINKS"
                        else "TAINT_STAGE_NOT_REQUESTED"
                    )
                    row["stage_gap_reason"] = {"code": reason_code, "explanation": reason}
                else:
                    incomplete = [
                        x for x in taint_calls
                        if x.get("status") in {
                            "NO_RESPONSE", "INCOMPLETE_RESPONSE", "COMPLETENESS_UNVERIFIED",
                            "MISSING_VISIBLE_OUTPUT", "MISSING_MARKER",
                            "UNINTERPRETABLE_CONCLUSION", "DUPLICATE_REQUEST_EVENTS",
                            "DUPLICATE_RESPONSE_EVENTS",
                        }
                    ]
                    if incomplete:
                        row["recovery_status"] = "TAINT_STAGE_PARTIAL_OR_UNINTERPRETABLE"
                        row["missing_stages"].append("TAINT_COMPLETE_RESPONSE")
                    elif any(x.get("has_error_event") for x in taint_calls):
                        row["recovery_status"] = "TAINT_REPORT_PRESERVED_WITH_ORIGINAL_ERROR_EVENT"
                    else:
                        row["recovery_status"] = "TAINT_REPORTS_PRESERVED"
                row["request_evidence"] = request_evidence
        row["evidence_artifact_path"] = evidence_snapshot_path(artifact).as_posix()
        records.append(row)

    return {
        "project_id": project_id,
        "case_ids": sorted(project_case_ids),
        "source_artifact": artifact,
        "evidence_artifact_path": evidence_snapshot_path(artifact).as_posix(),
        "original_project_status": result.get("status"),
        "original_project_result_sha256": sha(native_result),
        "source_file_count": len(records),
        "status": "PROJECT_EVIDENCE_PRESERVED",
        "files": records,
    }, dict(stage_totals)


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _build_recovery(input_path: Path, output: Path, validation: dict,
                    source_evidence: dict) -> dict:
    cases = validation["cases"]
    project_index = validation["project_index"]
    files_by_project = validation["files_by_project"]
    cases_by_project = validation["case_ids_by_project"]

    projects = {}
    for case in cases:
        pid = case["project_id"]
        artifact = case.get("execution_artifact")
        if pid in projects and projects[pid] != artifact:
            raise ValueError("CONFLICTING_PROJECT_EVIDENCE:" + pid)
        projects[pid] = artifact
    if len(projects) != 121:
        raise ValueError("EXPECTED_121_PROJECTS")

    project_dir = output / "projects"
    project_dir.mkdir()
    counts = Counter()
    project_reports = {}
    for pid, artifact in sorted(projects.items()):
        if artifact is None:
            report = {
                "project_id": pid, "case_ids": cases_by_project[pid],
                "source_artifact": None, "status": "SOURCE_ARTIFACT_MISSING",
                "missing_stages": ["SINK", "TAINT"], "files": [],
            }
            stages = {}
        else:
            report, stages = validate_project_artifact(
                pid, artifact, cases_by_project[pid], files_by_project[pid]
            )
        project_reports[pid] = report
        counts.update({"CALL_STAGE_" + key: value for key, value in stages.items()})
        counts["PROJECT_" + report["status"]] += 1
        for file_row in report.get("files", []):
            counts["FILE_RECOVERY_" + file_row.get("recovery_status", "UNKNOWN")] += 1
            ev = file_row.get("request_evidence") or {}
            for call in ev.get("entries", []):
                if call.get("stage") == "SINK":
                    counts["SINK_CALL_" + call.get("status", "UNKNOWN")] += 1
                if call.get("stage") == "TAINT":
                    counts["TAINT_CALL_" + call.get("status", "UNKNOWN")] += 1
                if call.get("has_error_event"):
                    counts["CALL_WITH_ERROR_EVENT"] += 1
        _write_json(project_dir / (pid + ".json"), report)

    manifest = {
        "schema": SCHEMA,
        "tool": "ACTaint",
        "dataset": "ACToolBench154",
        "case_count": len(cases),
        "project_count": len(project_index),
        "source_file_count": validation["validation"]["source_file_count"],
        "input_index_path": "datasets/actoolbench-cleaned-154/tools/actaint/input-index.json",
        "input_index_sha256": sha(INPUT_INDEX),
        "source_case_records_path": input_path.relative_to(ROOT).as_posix(),
        "source_case_records_sha256": sha(input_path),
        "label_boundary": validation["validation"],
        "ground_truth_read": False,
        "scoring_performed": False,
        "tp_fp_fn_fail_computed": False,
        "llm_requests_performed": 0,
        "source_evidence_manifest": "evidence/source-evidence-manifest.json",
        "source_run_seals": source_evidence["source_roots"],
        "source_evidence_file_count": source_evidence["file_count"],
        "counts": dict(sorted(counts.items())),
        "cases": [
            {
                "case_id": case["case_id"],
                "project_id": case["project_id"],
                "project_report": "projects/" + case["project_id"] + ".json",
                "source_execution_artifact": case.get("execution_artifact"),
                "original_case_status": case.get("status"),
                "case_project_mapping_validated": True,
            }
            for case in cases
        ],
    }
    _write_json(output / "recovery-manifest.json", manifest)
    return manifest


def recover(input_path: Path, output: Path, index_path: Path = INPUT_INDEX) -> dict:
    input_path = input_path.resolve()
    index_path = index_path.resolve()
    output = output.resolve()
    historical = (ROOT / "experiments").resolve()
    protected = [historical / name for name in (
        "llm-resume-20261027", "comparison-20261027-deepseek-high",
        "cache-optimization-20261027",
    )]
    if output == historical or any(output == path or path in output.parents for path in protected):
        raise ValueError("HISTORICAL_EVIDENCE_OUTPUT_FORBIDDEN")
    if output.exists():
        raise FileExistsError("RECOVERY_OUTPUT_MUST_NOT_EXIST:" + str(output))
    validation = validate_input_records(input_path, index_path)

    # Preflight the sealed source roots and every native artifact before writing output.
    # This guarantees an impossible mapping/hash aborts before any recovery artifact exists.
    for run_name in SOURCE_RUN_SPECS:
        _source_seal(run_name)
    cases = validation["cases"]
    projects = {}
    for case in cases:
        pid, artifact = case["project_id"], case.get("execution_artifact")
        if pid in projects and projects[pid] != artifact:
            raise ValueError("CONFLICTING_PROJECT_EVIDENCE:" + pid)
        projects[pid] = artifact
    if len(projects) != 121:
        raise ValueError("EXPECTED_121_PROJECTS")
    for pid, artifact in projects.items():
        if artifact is None:
            continue
        validate_project_artifact(
            pid, artifact, validation["case_ids_by_project"][pid],
            validation["files_by_project"][pid]
        )

    stage = output.with_name(output.name + f".staging-{os.getpid()}")
    if stage.exists():
        raise FileExistsError("RECOVERY_STAGING_ALREADY_EXISTS:" + str(stage))
    stage.mkdir(parents=True)
    try:
        source_evidence = snapshot_source_runs(stage)
        _write_json(stage / "evidence" / "source-evidence-manifest.json", source_evidence)
        manifest = _build_recovery(input_path, stage, validation, source_evidence)
        files = {
            path.relative_to(stage).as_posix(): sha(path)
            for path in stage.rglob("*")
            if path.is_file()
        }
        seal = {
            "schema": "ACTAINT_OFFLINE_RECOVERY_SEAL_V1",
            "tool": "ACTaint",
            "dataset": "ACToolBench154",
            "case_count": 154,
            "project_count": 121,
            "source_file_count": validation["validation"]["source_file_count"],
            "files": files,
            "source_roots_modified": False,
            "ground_truth_read": False,
            "scoring_performed": False,
            "tp_fp_fn_fail_computed": False,
            "llm_requests_performed": 0,
            "finished_utc": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(),
        }
        seal["seal_sha256"] = canonical_sha256(seal)
        _write_json(stage / "recovery-seal.json", seal)
        os.replace(stage, output)
        return manifest
    except Exception:
        # Preserve partial staging evidence for diagnosis; never overwrite or delete it.
        raise

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
