# ACTaint

**Paper Title:** ACTAINT: Agent-Based Taint Analysis for Access Control Vulnerabilities in Smart Contracts

## Quick Start

Run on Ubuntu 22.04 with Python 3.12.4:

```bash
python -m pip install -r requirements.txt
```

Create a repository-local `.env` file (do not commit it):

```dotenv
DEEPSEEK_API_KEY=replace-with-your-api-key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=replace-with-supported-model-name
CADG_LLM_PROVIDER=deepseek
LLM_REASONING_EFFORT=high
LLM_THINKING_ENABLED=true
LLM_TEMPERATURE=0
LLM_TOP_P=0.9

# Optional OpenAI-compatible fallback when no DeepSeek key is set:
# OPENAI_API_KEY=replace-with-your-api-key
# OPENAI_BASE_URL=https://your-openai-compatible-endpoint/v1
# OPENAI_MODEL=replace-with-supported-model-name
```

For a single Solidity input, set these paths in `.env` (the source file is relative to the dataset directory):

```dotenv
ACTAINT_DATASET_PATH=path/to/dataset
ACTAINT_SOL_FILE=path/relative/to/dataset/Contract.sol
```

Then start the tool:

```bash
sh start.sh
```

## Organization:

- `datasets`: All datasets
    - `clean_datasets`: Remove comments and empty lines, **used in our experiment**.
    - `raw_datasets`: raw, used as a reference

- `discussion`: The results used in our section Discussion.

- `experiment`: All experiment results

- `logs`: All logs

- `sol_name`: Name of the Solidity file

- `src`: source code     
    - `entities/`: Contains data and definitions.
    - `LLM/`: AI agents.
    - `config.py`: Configuration file **(Important)**

- `many.sh`: Script for batch execution (needs to be edited before use).

- `start.sh`: Script to start the program.


## Other Logs:

For the logs of GPTLens and AChecker, please visit [Other Logs](https://github.com/Smart-Contract-Security/ACTaint_Other)
