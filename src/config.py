import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

_REPO_ROOT = Path(__file__).resolve().parents[1]
if load_dotenv is not None:
    load_dotenv(_REPO_ROOT / ".env", override=False)

# DATASET_PATH = "datasets/clean_datasets/ACFix/"
# DATASET_PATH = "datasets/clean_datasets/624sol/"
DATASET_PATH = os.getenv("ACTAINT_DATASET_PATH", "datasets/clean_datasets/CVE/")
if DATASET_PATH and not DATASET_PATH.endswith(("/", "\\")):
    DATASET_PATH += os.sep

# ablation study
No_static = False
No_taint = False

# external library
# slither_library = []
# slither_library = ["solmate/=datasets/clean_datasets/ACFix/selfbuild/BondFixedExpiryTeller/lib/solmate/src/", "clones/=datasets/clean_datasets/ACFix/selfbuild/BondFixedExpiryTeller/lib/clones-with-immutable-args/src/"]
# slither_library = ["@openzeppelin/=datasets/clean_datasets/ACFix/selfbuild/StaxLPStaking/@openzeppelin/"]
# slither_library = ["@openzeppelin/=datasets/clean_datasets/ACFix/selfbuild/GymSinglePool/@openzeppelin/", "@quant-finance/=datasets/clean_datasets/ACFix/selfbuild/GymSinglePool/@quant-finance/"]
# slither_library = ["@openzeppelin/=datasets/@openzeppelin/"]
# slither_library = ["@openzeppelin/=datasets/clean_datasets/ACFix/selfbuild/MintableAutoCompundRelockBonus/@openzeppelin/"]
# slither_library = ["@openzeppelin/=datasets/clean_datasets/ACFix/self-build/QBridge/@openzeppelin/"]
# slither_library = ["solmate/=datasets/clean_datasets/ACFix/self-build/BondFixedExpiryTeller/lib/solmate/src/"]
# slither_library = ["@openzeppelin/=datasets/@openzeppelin/","@ensdomains=./datasets/@ensdomains"]
# slither_library = ["@openzeppelin/=datasets/clean_datasets/ACFix/StaxLPStaking/@openzeppelin/"]
# slither_library = ["solmate/=datasets/clean_datasets/ACFix/self-build/BondFixedExpiryTeller/lib/solmate/src/","clones/=datasets/clean_datasets/ACFix/self-build/BondFixedExpiryTeller/lib/clones-with-immutable-args/src/"]
# slither_library = ["@openzeppelin/=datasets/clean_datasets/ACFix/self-build/TreasureMarketplaceBuyer/@openzeppelin/"]
# slither_library = ["@openzeppelin/=datasets/clean_datasets/ACFix/self-build/Replica/node_modules/@openzeppelin/","@summa-tx=datasets/clean_datasets/ACFix/self-build/Replica/node_modules/@summa-tx/"]

slither_library = []

# Fixed DeepSeek protocol for the authorized comparison run.
gpt_provider = "deepseek"
gpt_url = os.getenv("DEEPSEEK_BASE_URL") or "https://api.deepseek.com"
gpt_key = os.getenv("DEEPSEEK_API_KEY", "")
gpt_model = "deepseek-flash"
gpt_reasoning_effort = "high"
gpt_thinking_enabled = True
gpt_max_tokens = 65536
gpt_request_timeout = 300
gpt_max_retries = 0

total_token = 0

SOL_FILE = os.getenv("ACTAINT_SOL_FILE", "CVE-2018-10666.sol")
SOL_FILE_PATH = DATASET_PATH + SOL_FILE
