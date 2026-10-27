#!/usr/bin/env python3
"""Run the native ACTaint analyzer once for a unique ACToolBench project group.

Each project contains every ACTaint-indexed Solidity file and may be linked to
multiple case IDs. The runner records one file disposition per indexed source;
shared case IDs are mapped to that project result instead of repeating calls.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_RELATIVE = Path("datasets/actoolbench-cleaned-154/full")
INDEX_RELATIVE = Path("datasets/actoolbench-cleaned-154/tools/actaint/input-index.json")
MANIFEST_RELATIVE = Path("datasets/actoolbench-cleaned-154/full/manifest.json")
SCHEMA = "ACTAINT_PROJECT_RUN_V1"
RUN_CONFIG = {
    "provider": "deepseek",
    "model": "deepseek-flash",
    "reasoning_effort": "high",
    "thinking": {"type": "enabled"},
    "max_tokens": 65536,
    "request_timeout_seconds": 300,
    "project_group_timeout_seconds": 1200,
    "automatic_retries": 0,
    "concurrency": 2,
    "temperature": None,
    "top_p": None,
}


class RunError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".tmp-{os.getpid()}")
    temp.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temp, path)


def _safe_relative(value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise RunError(f"INVALID_{field.upper()}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise RunError(f"UNSAFE_{field.upper()}")
    return Path(*path.parts)


def _reject_label_fields(record: dict[str, Any], scope: str) -> None:
    forbidden = {
        "label", "labels", "vulnerability_type", "vuln_type", "root_cause",
        "ground_truth", "vulnerable_function", "function_name", "reported_issue",
        "adjudication", "reference_status",
    }
    if forbidden.intersection(key.lower() for key in record):
        raise RunError(f"LABEL_FIELD_IN_TOOL_INDEX:{scope}")


def _load_json(path: Path, error_code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        raise RunError(error_code) from None
    if not isinstance(value, dict):
        raise RunError(error_code)
    return value


def load_plan(repo_root: Path = REPO_ROOT, index_path: Path | None = None) -> dict[str, Any]:
    """Validate the tool index, its linked source records, and the label boundary."""
    repo_root = repo_root.resolve()
    index_path = (index_path or repo_root / INDEX_RELATIVE).resolve()
    dataset_root = (repo_root / DATASET_RELATIVE).resolve()
    if not dataset_root.is_dir() or not dataset_root.is_relative_to(repo_root):
        raise RunError("DATASET_ROOT_UNAVAILABLE")
    index = _load_json(index_path, "INPUT_INDEX_UNREADABLE")
    if index.get("tool", "").lower() != "actaint":
        raise RunError("INPUT_INDEX_TOOL_MISMATCH")
    if index.get("dataset_id") != "actoolbench-cleaned-154":
        raise RunError("INPUT_INDEX_DATASET_MISMATCH")
    if index.get("case_labels_included") is not False:
        raise RunError("TOOL_INDEX_LABEL_BOUNDARY_INVALID")

    cases, source_rows, project_rows = index.get("cases"), index.get("files"), index.get("projects")
    if not isinstance(cases, list) or len(cases) != 154:
        raise RunError("EXPECTED_154_CASE_RECORDS")
    if not isinstance(source_rows, list) or len(source_rows) != 694:
        raise RunError("EXPECTED_694_TOOL_INPUT_FILES")
    if not isinstance(project_rows, list) or len(project_rows) != 121:
        raise RunError("EXPECTED_121_PROJECT_INDEX_ROWS")

    file_index: dict[str, dict[str, Any]] = {}
    for row in source_rows:
        if not isinstance(row, dict):
            raise RunError("INVALID_SOURCE_FILE_INDEX_ROW")
        _reject_label_fields(row, "source_file")
        rel = _safe_relative(row.get("tool_input_path"), "tool_input_path").as_posix()
        if rel in file_index or not rel.endswith(".sol"):
            raise RunError("DUPLICATE_OR_NON_SOLIDITY_TOOL_INPUT")
        path = (dataset_root / _safe_relative(rel, "tool_input_path")).resolve()
        if not path.is_relative_to(dataset_root) or not path.is_file():
            raise RunError("TOOL_INPUT_SOURCE_MISSING")
        expected = row.get("sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise RunError("TOOL_INPUT_SOURCE_HASH_INVALID")
        if _sha256(path) != expected:
            raise RunError(f"TOOL_INPUT_SOURCE_HASH_MISMATCH:{rel}")
        if row.get("bytes") is not None and path.stat().st_size != row["bytes"]:
            raise RunError(f"TOOL_INPUT_SOURCE_SIZE_MISMATCH:{rel}")
        file_index[rel] = row

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_case_ids: set[str] = set()
    for row in cases:
        if not isinstance(row, dict):
            raise RunError("INVALID_CASE_INDEX_ROW")
        _reject_label_fields(row, "case")
        case_id, project_id = row.get("case_id"), row.get("project_id")
        if not isinstance(case_id, str) or not case_id or case_id in seen_case_ids:
            raise RunError("INVALID_OR_DUPLICATE_CASE_ID")
        if not isinstance(project_id, str) or not re.fullmatch(r"proj-[0-9a-f]{16}", project_id):
            raise RunError("INVALID_PROJECT_ID")
        seen_case_ids.add(case_id)
        raw_files = row.get("tool_input_files")
        if not isinstance(raw_files, list) or not raw_files:
            raise RunError("CASE_HAS_NO_TOOL_INPUT_FILES")
        file_paths = [_safe_relative(path, "tool_input_file").as_posix() for path in raw_files]
        if len(set(file_paths)) != len(file_paths) or any(path not in file_index for path in file_paths):
            raise RunError("CASE_TOOL_INPUT_MAPPING_INVALID")
        if row.get("source_file_count") != len(file_paths):
            raise RunError("CASE_SOURCE_COUNT_MISMATCH")
        config_rel = _safe_relative(row.get("compile_config_path"), "compile_config_path").as_posix()
        prefix = "datasets/actoolbench-cleaned-154/full/"
        if config_rel.startswith(prefix):
            config_rel = config_rel.removeprefix(prefix)
        if not config_rel.startswith(f"projects/{project_id}/source_code/"):
            raise RunError("CASE_CONFIG_PROJECT_MISMATCH")
        groups[project_id].append({
            "case_id": case_id,
            "project_id": project_id,
            "compile_config_path": config_rel,
            "tool_input_files": file_paths,
        })

    project_index = {row.get("project_id"): row for row in project_rows if isinstance(row, dict)}
    if len(project_index) != 121:
        raise RunError("DUPLICATE_OR_INVALID_PROJECT_INDEX")
    projects = []
    for project_id, linked_cases in groups.items():
        indexed = project_index.get(project_id)
        if not indexed or indexed.get("case_count") != len(linked_cases):
            raise RunError(f"PROJECT_CASE_COUNT_MISMATCH:{project_id}")
        file_sets = {tuple(row["tool_input_files"]) for row in linked_cases}
        config_paths = {row["compile_config_path"] for row in linked_cases}
        if len(file_sets) != 1 or len(config_paths) != 1:
            raise RunError(f"SHARED_PROJECT_MAPPING_MISMATCH:{project_id}")
        file_set = list(next(iter(file_sets)))
        config_rel = next(iter(config_paths))
        if indexed.get("source_file_count") != len(file_set):
            raise RunError(f"PROJECT_SOURCE_COUNT_MISMATCH:{project_id}")
        config_path = (dataset_root / _safe_relative(config_rel, "compile_config_path")).resolve()
        if not config_path.is_relative_to(dataset_root) or not config_path.is_file():
            raise RunError(f"PROJECT_COMPILE_CONFIG_MISSING:{project_id}")
        config = _load_json(config_path, f"PROJECT_COMPILE_CONFIG_INVALID:{project_id}")
        source_root = (dataset_root / Path("projects") / project_id / "source_code").resolve()
        if not source_root.is_relative_to(dataset_root) or not source_root.is_dir():
            raise RunError(f"PROJECT_SOURCE_ROOT_MISSING:{project_id}")
        project_files = []
        for rel in file_set:
            row = file_index[rel]
            project_files.append({
                "tool_input_path": rel,
                "source_repo_path": _safe_relative(row.get("source_path"), "source_path").as_posix(),
                "sha256": row["sha256"],
                "bytes": row.get("bytes"),
            })
        projects.append({
            "project_id": project_id,
            "case_ids": sorted(row["case_id"] for row in linked_cases),
            "compile_config_path": config_rel,
            "compile_config_sha256": _sha256(config_path),
            "compiler_version_metadata": config.get("CompilerVersion") or config.get("compiler_version"),
            "compile_config": config,
            "source_root": f"projects/{project_id}/source_code",
            "files": sorted(project_files, key=lambda row: row["tool_input_path"]),
        })

    manifest_path = repo_root / MANIFEST_RELATIVE
    manifest = _load_json(manifest_path, "SOURCE_MANIFEST_UNREADABLE")
    manifest_cases = manifest.get("cases")
    if not isinstance(manifest_cases, list) or len(manifest_cases) != 154:
        raise RunError("SOURCE_MANIFEST_CASE_COUNT_MISMATCH")
    manifest_ids = [row.get("case_id") for row in manifest_cases if isinstance(row, dict)]
    if len(set(manifest_ids)) != 154 or set(manifest_ids) != seen_case_ids:
        raise RunError("SOURCE_MANIFEST_CASE_ID_MISMATCH")
    if len(projects) != 121:
        raise RunError("EXPECTED_121_UNIQUE_PROJECTS")

    return {
        "dataset_id": index["dataset_id"],
        "source_repository_commit": index.get("source_repository_commit"),
        "input_index_sha256": _sha256(index_path),
        "manifest_sha256": _sha256(manifest_path),
        "case_count": len(cases),
        "project_count": len(projects),
        "unique_solidity_file_count": len(file_index),
        "dataset_root": dataset_root,
        "projects": sorted(projects, key=lambda row: row["project_id"]),
    }


def _extract_semver(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str):
        return None, None
    match = re.search(r"(?<!\d)(\d+\.\d+\.\d+)(?:\+commit\.([0-9a-fA-F]+))?", value)
    return (match.group(1), match.group(2).lower() if match.group(2) else None) if match else (None, None)


def _vtuple(value: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in value.split("."))


def _pragma_matches(version: str, clause: str) -> bool | None:
    alternatives = [item.strip() for item in clause.split("||")]
    if not alternatives or any(not item for item in alternatives):
        return None
    target = _vtuple(version)
    for alternative in alternatives:
        terms = list(re.finditer(r"(>=|<=|>|<|\^|~|=)?\s*(\d+\.\d+\.\d+)", alternative))
        residue = re.sub(r"(>=|<=|>|<|\^|~|=)?\s*\d+\.\d+\.\d+", "", alternative)
        if not terms or re.sub(r"[\s,]", "", residue):
            return None
        accepted = True
        for term in terms:
            op, bound = term.group(1) or "=", _vtuple(term.group(2))
            if op == "^":
                upper = ((bound[0] + 1, 0, 0) if bound[0] else
                         ((0, bound[1] + 1, 0) if bound[1] else (0, 0, bound[2] + 1)))
                accepted &= target >= bound and target < upper
            elif op == "~":
                accepted &= target >= bound and target < (bound[0], bound[1] + 1, 0)
            elif op == ">=": accepted &= target >= bound
            elif op == "<=": accepted &= target <= bound
            elif op == ">": accepted &= target > bound
            elif op == "<": accepted &= target < bound
            else: accepted &= target == bound
        if accepted:
            return True
    return False


def _pragma_version(project: dict[str, Any], dataset_root: Path, available: set[str]) -> tuple[str | None, str | None]:
    pragmas = []
    for row in project["files"]:
        path = dataset_root / _safe_relative(row["tool_input_path"], "source_path")
        text = path.read_text(encoding="utf-8", errors="replace")
        pragmas.extend(re.findall(r"pragma\s+solidity\s+([^;]+);", text))
    if not pragmas:
        return None, None
    for version in sorted(available, key=_vtuple, reverse=True):
        matches = [_pragma_matches(version, item.strip()) for item in pragmas]
        if any(result is None for result in matches):
            return None, None
        if all(matches):
            return version, "pragma_highest_available_satisfying_all_project_sources"
    return None, None


def load_compiler_map(path: Path) -> dict[str, dict[str, Any]]:
    raw = _load_json(path, "COMPILER_MAP_UNREADABLE")
    if raw.get("schema") != "COMPARISON_SOLC_MAP_V1" or not isinstance(raw.get("versions"), dict):
        raise RunError("COMPILER_MAP_SCHEMA_INVALID")
    result = {}
    for version, row in raw["versions"].items():
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(version)):
            raise RunError("COMPILER_MAP_VERSION_INVALID")
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise RunError(f"COMPILER_MAP_ENTRY_INVALID:{version}")
        binary = Path(row["path"])
        if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
            raise RunError(f"COMPILER_BINARY_UNAVAILABLE:{version}")
        try:
            output = subprocess.run([str(binary), "--version"], capture_output=True, text=True,
                                    check=True, timeout=15).stdout
        except (OSError, subprocess.SubprocessError):
            raise RunError(f"COMPILER_VERSION_CHECK_FAILED:{version}") from None
        match = re.search(r"Version:\s*(\d+\.\d+\.\d+)(?:\+commit\.([0-9a-fA-F]+))?", output)
        if not match or match.group(1) != version:
            raise RunError(f"COMPILER_SEMVER_MISMATCH:{version}")
        digest = _sha256(binary)
        if row.get("sha256") and row["sha256"] != digest:
            raise RunError(f"COMPILER_HASH_MISMATCH:{version}")
        result[version] = {
            "path": str(binary.resolve()),
            "version": match.group(1),
            "build": match.group(2).lower() if match.group(2) else None,
            "sha256": digest,
        }
    return result


def _compile_args(config: dict[str, Any], source_root: Path, compiler_version: str) -> tuple[str, list[str]]:
    optimize_raw = config.get("optimize", config.get("OptimizationUsed", False))
    optimized = str(optimize_raw).lower() in {"true", "1", "yes"}
    via_ir = str(config.get("via-ir", config.get("viaIR", False))).lower() in {"true", "1", "yes"}
    runs = config.get("runs", config.get("Runs"))
    args = []
    if optimized:
        args.append("--optimize")
        if runs is not None and str(runs).isdigit():
            args.extend(["--optimize-runs", str(runs)])
    if via_ir and _vtuple(compiler_version) >= (0, 8, 13):
        args.append("--via-ir")
    if _vtuple(compiler_version) >= (0, 6, 9):
        args.extend(["--base-path", str(source_root)])
    evm = config.get("evmVersion", config.get("EVMVersion"))
    if isinstance(evm, str) and evm.lower() not in {"", "default"}:
        args.extend(["--evm-version", evm])
    remappings = config.get("remappings", config.get("Remappings", []))
    if isinstance(remappings, str):
        remappings = remappings.split()
    if not isinstance(remappings, list):
        remappings = []
    return " ".join(args), [item for item in remappings if isinstance(item, str)]


def _compiler_for_project(project: dict[str, Any], plan: dict[str, Any],
                          compiler_map: dict[str, dict[str, Any]]) -> dict[str, Any]:
    raw = project.get("compiler_version_metadata")
    version, metadata_build = _extract_semver(raw)
    selection_rule = "project_compile_config"
    if version is None:
        version, selection_rule = _pragma_version(project, plan["dataset_root"], set(compiler_map))
        if version is None:
            return {"status": "ERROR_INPUT_COMPILER_UNRESOLVED",
                    "metadata": raw, "selection_rule": "pragma_unresolved"}
    entry = compiler_map.get(version)
    if entry is None:
        return {"status": "ERROR_SOLC_UNAVAILABLE", "metadata": raw,
                "selection_rule": selection_rule, "version": version}
    full = entry["version"] + (f"+commit.{entry['build']}" if entry["build"] else "")
    args, remappings = _compile_args(project["compile_config"],
                                     plan["dataset_root"] / project["source_root"], version)
    return {
        "status": "READY", "metadata": raw, "selection_rule": selection_rule,
        "version": version, "actual_full_version": full, "metadata_build": metadata_build,
        "metadata_build_match": None if metadata_build is None else metadata_build == entry["build"],
        "compiler_sha256": entry["sha256"], "compiler_path": entry["path"],
        "solc_args": args, "solc_remappings": remappings,
    }


def _redact_native_paths(text: str, repo_root: Path) -> str:
    for source, replacement in (
        (str(repo_root.resolve()), "$REPO_ROOT"),
        ("/home/shanzy", "$HOME"),
        ("/add/users/shanzy", "$SHANZY_WORKSPACE"),
    ):
        text = text.replace(source, replacement)
    return text


def _terminate_child(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _summary_from_stdout(path: Path) -> dict[str, Any] | None:
    marker = "ACTAINT_ANALYZER_SUMMARY_JSON="
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        if line.startswith(marker):
            try:
                value = json.loads(line[len(marker):])
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, dict) else None
    return None


def _global_provider_stop_path() -> Path | None:
    value = os.environ.get("EXPERIMENT_GLOBAL_STOP_FILE")
    return Path(value) if value else None


def _mark_global_provider_stop() -> None:
    path = _global_provider_stop_path()
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        temp = path.with_name(path.name + f".tmp-{os.getpid()}")
        temp.write_text(json.dumps({"status": "STOPPED_AUTH_OR_PAYMENT_ERROR", "tool": "ACTaint"}) + "\n")
        os.replace(temp, path)


def _request_log_requires_provider_stop(path: Path) -> bool:
    """Fail closed after authentication/payment errors; malformed logs are unsafe to continue."""
    if not path.is_file():
        return False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return True
        if row.get("event") != "error":
            continue
        code = row.get("status_code", row.get("http_status"))
        try:
            code = int(code)
        except (TypeError, ValueError):
            code = None
        body = row.get("error_body", {})
        provider_code = body.get("error", {}).get("code") if isinstance(body, dict) else None
        if code in (401, 402, 403) or provider_code in {
            "insufficient_balance_error", "insufficient_quota", "payment_required", "billing_hard_limit_reached"
        }:
            return True
    return False


def run_project(
    plan: dict[str, Any], project_id: str, output_dir: Path,
    compiler_map: dict[str, dict[str, Any]], *, code_sha: str,
    timeout_seconds: int = 1200, prompt_layout: str = "baseline",
    repo_root: Path = REPO_ROOT, analyzer_path: Path | None = None,
    python_bin: str | None = None,
) -> dict[str, Any]:
    if timeout_seconds != 1200:
        raise RunError("PROJECT_GROUP_TIMEOUT_MUST_BE_1200_SECONDS")
    if prompt_layout not in {"baseline", "prefix_stable", "prefix_stable_v2"}:
        raise RunError("INVALID_PROMPT_LAYOUT")
    project = next((row for row in plan["projects"] if row["project_id"] == project_id), None)
    if project is None:
        raise RunError("UNKNOWN_PROJECT_ID")
    output_dir = output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise RunError("OUTPUT_EXISTS_NO_REPLAY")
    output_dir.mkdir(parents=True, exist_ok=True)
    files_dir = output_dir / "files"
    files_dir.mkdir(exist_ok=True)
    analyzer_path = (analyzer_path or (repo_root / "src/analyze_smart_contract.py")).resolve()
    python_bin = python_bin or sys.executable
    dataset_root = plan["dataset_root"]
    started = time.monotonic()
    deadline = started + timeout_seconds
    compiler = _compiler_for_project(project, plan, compiler_map)
    result = {
        "schema": SCHEMA, "tool": "ACTaint", "dataset_id": plan["dataset_id"],
        "project_id": project_id, "case_ids": project["case_ids"],
        "record_count": len(project["case_ids"]), "source_file_count": len(project["files"]),
        "compile_config_path": project["compile_config_path"],
        "compile_config_sha256": project["compile_config_sha256"],
        "source_repository_commit": plan.get("source_repository_commit"),
        "source_manifest_sha256": plan["manifest_sha256"],
        "input_index_sha256": plan["input_index_sha256"],
        "code_sha": code_sha, "prompt_layout": prompt_layout,
        "run_config": RUN_CONFIG, "ground_truth_read": False,
        "compiler": {key: value for key, value in compiler.items() if key != "compiler_path"},
        "started_utc": _utc_now(), "ended_utc": None, "status": "RUNNING",
        "file_results": [],
    }
    _atomic_json(output_dir / "project-result.json", result)
    for index, row in enumerate(project["files"]):
        rel = row["tool_input_path"]
        file_dir = files_dir / hashlib.sha256(rel.encode("utf-8")).hexdigest()[:16]
        file_dir.mkdir(exist_ok=False)
        file_path = (dataset_root / _safe_relative(rel, "tool_input_path")).resolve()
        file_result = {
            "tool_input_path": rel, "source_repo_path": row["source_repo_path"],
            "source_sha256": row["sha256"], "actual_source_sha256": _sha256(file_path),
            "status": "PENDING", "started_utc": None, "ended_utc": None,
        }
        request_log: Path | None = None
        global_stop = _global_provider_stop_path()
        if global_stop is not None and global_stop.exists():
            file_result.update(status="NOT_RUN_GLOBAL_PROVIDER_STOP", ended_utc=_utc_now())
        elif file_result["actual_source_sha256"] != row["sha256"]:
            file_result.update(status="ERROR_SOURCE_HASH_MISMATCH", ended_utc=_utc_now())
        elif compiler["status"] != "READY":
            file_result["compiler"] = result["compiler"]
            file_result.update(status=compiler["status"], ended_utc=_utc_now())
        else:
            file_result["compiler"] = result["compiler"]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                file_result.update(status="NOT_RUN_CASE_TIMEOUT", ended_utc=_utc_now())
            else:
                request_log = file_dir / "requests.jsonl"
                env = os.environ.copy()
                env.update({
                    "ACTAINT_DATASET_PATH": str(dataset_root) + os.sep,
                    "ACTAINT_SOL_FILE": rel,
                    "ACTAINT_SOLC_BINARY": compiler["compiler_path"],
                    "ACTAINT_SOLC_REMAPPINGS_JSON": json.dumps(compiler["solc_remappings"], ensure_ascii=False),
                    "ACTAINT_SOLC_ARGS_JSON": json.dumps(compiler["solc_args"].split(), ensure_ascii=False),
                    "ACTAINT_COMPILATION_CWD": str((dataset_root / project["source_root"]).resolve()),
                    "EXPERIMENT_DATASET": plan["dataset_id"],
                    "EXPERIMENT_PROJECT_ID": project_id,
                    "EXPERIMENT_CASE_IDS": json.dumps(project["case_ids"], ensure_ascii=False),
                    "EXPERIMENT_CASE_ID": project["case_ids"][0] if len(project["case_ids"]) == 1 else "",
                    "EXPERIMENT_SOURCE_FILE": rel,
                    "ACTAINT_PROMPT_LAYOUT": prompt_layout,
                    "TOOL_REQUEST_LOG_FILE": str(request_log),
                })
                stdout_path, stderr_path = file_dir / "stdout.txt", file_dir / "stderr.txt"
                file_result["started_utc"] = _utc_now()
                _atomic_json(file_dir / "status.json", file_result)
                process = None
                try:
                    with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                        process = subprocess.Popen(
                            [python_bin, "-B", str(analyzer_path)], cwd=str(repo_root), env=env,
                            stdout=stdout_file, stderr=stderr_file,
                        )
                        try:
                            exit_code = process.wait(timeout=max(0.01, remaining))
                            status = "COMPLETED" if exit_code == 0 else "ERROR"
                        except subprocess.TimeoutExpired:
                            _terminate_child(process)
                            exit_code, status = None, "TIMEOUT"
                    stdout_path.write_text(
                        _redact_native_paths(stdout_path.read_text(encoding="utf-8", errors="replace"), repo_root),
                        encoding="utf-8", newline="\n")
                    stderr_path.write_text(
                        _redact_native_paths(stderr_path.read_text(encoding="utf-8", errors="replace"), repo_root),
                        encoding="utf-8", newline="\n")
                    file_result.update(
                        status=status, exit_code=exit_code, ended_utc=_utc_now(),
                        elapsed_seconds=round(time.monotonic() - started, 3),
                        analyzer_summary=_summary_from_stdout(stdout_path),
                        request_log_path=request_log.relative_to(output_dir).as_posix() if request_log.exists() else None,
                    )
                    if status == "COMPLETED" and file_result["analyzer_summary"] is None:
                        file_result["status"] = "ERROR_ANALYZER_SUMMARY_MISSING"
                except OSError as exc:
                    file_result.update(
                        status="ERROR_PROCESS_START", error_type=type(exc).__name__, ended_utc=_utc_now())
                finally:
                    if process is not None and process.poll() is None:
                        _terminate_child(process)

        _atomic_json(file_dir / "status.json", file_result)
        result["file_results"].append(file_result)
        _atomic_json(output_dir / "project-result.json", result)
        if request_log is not None and _request_log_requires_provider_stop(request_log):
            result["provider_stop"] = True
            _mark_global_provider_stop()
            for pending in project["files"][len(result["file_results"]):]:
                pending_dir = files_dir / hashlib.sha256(pending["tool_input_path"].encode("utf-8")).hexdigest()[:16]
                pending_dir.mkdir(exist_ok=False)
                pending_result = {
                    "tool_input_path": pending["tool_input_path"],
                    "source_repo_path": pending["source_repo_path"],
                    "source_sha256": pending["sha256"],
                    "status": "NOT_RUN_GLOBAL_PROVIDER_STOP",
                    "started_utc": None, "ended_utc": _utc_now(),
                }
                result["file_results"].append(pending_result)
                _atomic_json(pending_dir / "status.json", pending_result)
            _atomic_json(output_dir / "project-result.json", result)
            break
        if file_result["status"] == "TIMEOUT":
            for pending in project["files"][len(result["file_results"]):]:
                pending_dir = files_dir / hashlib.sha256(pending["tool_input_path"].encode("utf-8")).hexdigest()[:16]
                pending_dir.mkdir(exist_ok=False)
                pending_result = {
                    "tool_input_path": pending["tool_input_path"],
                    "source_repo_path": pending["source_repo_path"],
                    "source_sha256": pending["sha256"],
                    "status": "NOT_RUN_CASE_TIMEOUT",
                    "started_utc": None, "ended_utc": _utc_now(),
                }
                result["file_results"].append(pending_result)
                _atomic_json(pending_dir / "status.json", pending_result)
            break

    statuses = [row["status"] for row in result["file_results"]]
    timed_out = any(status in {"TIMEOUT", "NOT_RUN_CASE_TIMEOUT"} for status in statuses)
    errors = any(status == "ERROR" or status.startswith("ERROR_") for status in statuses)
    result.update(
        status="PROJECT_TIMEOUT" if timed_out else ("PROJECT_WITH_ERRORS" if errors else "PROJECT_COMPLETED"),
        ended_utc=_utc_now(),
        elapsed_seconds=round(time.monotonic() - started, 3),
    )
    _atomic_json(output_dir / "project-result.json", result)
    return result


def _local_code_fingerprint(repo_root: Path) -> str:
    paths = [
        "src/config.py", "src/analyze_smart_contract.py", "src/llm/call_gpt.py",
        "src/llm/sink_agent.py", "src/llm/taint_agent.py", "src/utils.py",
    ]
    parts = []
    for relative in paths:
        path = repo_root / relative
        parts.append(f"{relative}:{_sha256(path) if path.is_file() else 'MISSING'}")
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-id")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compiler-map", type=Path)
    parser.add_argument("--prompt-layout", choices=("baseline", "prefix_stable", "prefix_stable_v2"), default="baseline")
    parser.add_argument("--code-sha", default=os.getenv("COMPARISON_CODE_SHA"))
    parser.add_argument("--index", type=Path, default=REPO_ROOT / INDEX_RELATIVE)
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        plan = load_plan(REPO_ROOT, args.index.resolve())
        if args.validate_only:
            print(json.dumps({
                "dataset_id": plan["dataset_id"], "case_count": plan["case_count"],
                "unique_project_count": plan["project_count"],
                "unique_solidity_file_count": plan["unique_solidity_file_count"],
                "project_ids": [row["project_id"] for row in plan["projects"]],
                "input_index_sha256": plan["input_index_sha256"],
                "manifest_sha256": plan["manifest_sha256"],
                "ground_truth_read": False, "status": "INPUT_INDEX_VALIDATED",
            }, ensure_ascii=False, sort_keys=True))
            return 0
        if not args.project_id or args.output is None or args.compiler_map is None:
            raise RunError("PROJECT_ID_OUTPUT_AND_COMPILER_MAP_REQUIRED")
        compiler_map = load_compiler_map(args.compiler_map.resolve())
        code_sha = args.code_sha or _local_code_fingerprint(REPO_ROOT)
        result = run_project(
            plan, args.project_id, args.output, compiler_map, code_sha=code_sha,
            timeout_seconds=args.timeout_seconds, prompt_layout=args.prompt_layout,
        )
        print(json.dumps({
            "project_id": result["project_id"], "case_ids": result["case_ids"],
            "status": result["status"],
            "file_statuses": [row["status"] for row in result["file_results"]],
        }, ensure_ascii=False, sort_keys=True))
        return 0 if result["status"] == "PROJECT_COMPLETED" else 4
    except RunError as exc:
        print(json.dumps({"status": "PREFLIGHT_OR_RUN_ERROR", "reason_code": str(exc)}, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
