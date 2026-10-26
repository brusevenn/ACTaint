# ACToolBench-cleaned-154 input package for ACTaint

This is a dataset-only adaptation for `ACTaint`. No detector/research code was changed, and no detector run, compilation, or evaluation was performed during packaging.

**Target execution platform: Ubuntu 22.04 LTS.** Run the commands below from the repository root with POSIX paths. Each project needs its own compatible Python environment; this dataset packaging did not provision or test those environments.

## Contents and provenance

- Source: [`brusevenn/smart-contract-AC-detector`](https://github.com/brusevenn/smart-contract-AC-detector), `main`, commit `99b0ad9f39ee54a7d9645ac693dd74e9d4479f7e`.
- Original full manifest: [`full/manifest.json`](full/manifest.json), copied byte-for-byte from `datasets/actoolbench-cleaned/full/manifest.json` (Git blob SHA-1 `9d4160fca8ff05ca2ab105deb8db732564829e79`, SHA-256 `9c74d0a6c647543e80cced49044639b7a8c40e241fc8593c21e574210584b5fa`).
- Source trees: `full/projects/<project_id>/source_code/`, including each project's original `config.json` and all Solidity sources/dependencies.
- Upstream license: [`UPSTREAM_LICENSE`](UPSTREAM_LICENSE).
- `file-hashes.jsonl` records each copied project/config file's repository-relative path, byte count, SHA-256, Git blob SHA-1, project ID, and role. The manifest's per-source SHA-256 values are retained unchanged.
- `tools/actaint/input-index.json` preserves the case-to-project mapping and this tool's input paths; `source-files.txt` is the tool-ready unique Solidity input list.

Counts: **154 case records**, **121 project trees**, **694 unique Solidity files**, and **121 compile configuration files**. Multiple case records can share a project tree; the tool input list is therefore a list of unique source files, not 154 independently selected contracts. Use the case mapping in `input-index.json` when relating tool results back to records.

## Label boundary

Only source/config files are intended as detector input. The case manifest and tool index contain opaque case/project identifiers and source paths/hashes, but no per-case vulnerability type, official function name, root-cause description, or adjudication result. Do not pass `full/manifest.json`, `input-index.json`, `file-hashes.jsonl`, or `source-files.txt` into the model prompt; use only the `.sol` files through the tool's normal loader. The copied manifest has global dataset metadata but no case-level label assignments.

Source bytes, including original comments and formatting, are preserved. No evaluation-side files were copied. The upstream manifest records `source_compile_status: NOT_EXECUTED`; compiler compatibility is not implied by this package.

## ACTaint input layout and limitations

The ACTaint README specifies Python 3.12.4; on Ubuntu 22.04 use a separate 3.12.4 interpreter/virtual environment rather than the system Python.

- `tools/actaint/source-files.txt` contains 694 Solidity paths relative to `datasets/actoolbench-cleaned-154/full/`.
- `src/config.py` currently points `DATASET_PATH` at the repository's existing CVE data. For this corpus, set it locally to `datasets/actoolbench-cleaned-154/full/`; the list entries are then valid `SOL_FILE` values.
- Example from the repository root (the native `run_files.py` rewrites `src/config.py` for each file, so back up and restore that file around a run):

```sh
while IFS= read -r sol; do
  python3.12 src/run_files.py "$sol"
  python3.12 src/select_solc_version.py
  python3.12 src/analyze_smart_contract.py
done < datasets/actoolbench-cleaned-154/tools/actaint/source-files.txt
```

ACTaint's analyzer consumes one Solidity file at a time. Its current runner does not automatically apply each project's `config.json` compiler remappings; imports/remappings or compiler versions may need manual setup. No API key is stored here.
