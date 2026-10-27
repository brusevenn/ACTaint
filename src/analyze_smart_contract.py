from slither.slither import Slither
from slither.slithir.operations import Transfer,Assignment,Send,Condition,LowLevelCall
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.slithir.operations.binary import Binary
from slither.slithir.operations.solidity_call import SolidityCall
from slither.slithir.variables.temporary import TemporaryVariable
from slither.slithir.variables.state_variable import StateVariable
from slither.core.cfg.node import NodeType
from build_cv_graph import BuildCVGraph
from entities.cv_node import CVNode
from utils import read_source_code
from llm.sink_agent import SinkAgent
from llm.taint_agent import TaintAgent
from entities.message import Message
import config
import json
import os
from pathlib import Path
import time

# convert to source code
def parse_to_source(path_dict):
    source_dict = {}
    for key, value in path_dict.items():
        if len(value) == 0:
            continue
        
        key_souce = str(key)
        value_source = ""
        # Before converting the value, check first. If there is no function in the value, it means that no function is written to cv, so just set the value to empty.
        if not any(obj.get_type() == 1 for obj in value):
            source_dict[key_souce] = value_source
            continue

        for obj in reversed(value):
            value_source += f"{read_source_code(str(obj.get_node().source_mapping))}"

        source_dict[key_souce] = value_source

    return source_dict

def _is_target_source(contract, target_path):
    target = Path(target_path).resolve()
    filename = getattr(getattr(contract, "source_mapping", None), "filename", None)
    if filename is None:
        return False
    bases = [
        Path(os.getenv("ACTAINT_COMPILATION_CWD", Path.cwd())),
        Path.cwd(),
    ]
    for attribute in ("absolute", "short", "relative"):
        value = getattr(filename, attribute, None)
        if callable(value):
            value = value()
        if not value:
            continue
        candidate = Path(str(value))
        candidates = [candidate] if candidate.is_absolute() else [base / candidate for base in bases]
        for item in candidates:
            try:
                if item.resolve() == target:
                    return True
            except OSError:
                continue
    return False


def get_unaffect_functions(nodes):
    functions = []
    for node in nodes:
        if node.get_type() == 1 and node.in_edges == []:
            functions.append(node)
    return functions

if __name__ == "__main__":
    start_time = time.time()
    print("==============Start====================")
    config.total_token = 0

    slither_kwargs = {"solc_remaps": config.slither_library}
    compiler_binary = os.getenv("ACTAINT_SOLC_BINARY")
    compilation_cwd = os.getenv("ACTAINT_COMPILATION_CWD")
    if compiler_binary:
        remappings = json.loads(os.getenv("ACTAINT_SOLC_REMAPPINGS_JSON", "[]"))
        solc_args = json.loads(os.getenv("ACTAINT_SOLC_ARGS_JSON", "[]"))
        if not isinstance(remappings, list) or not all(isinstance(item, str) for item in remappings):
            raise ValueError("ACTAINT_SOLC_REMAPPINGS_JSON must be a list of strings")
        if not isinstance(solc_args, list) or not all(isinstance(item, str) for item in solc_args):
            raise ValueError("ACTAINT_SOLC_ARGS_JSON must be a list of strings")
        slither_kwargs.update(solc=compiler_binary, solc_remaps=remappings)
        if compilation_cwd:
            slither_kwargs["cwd"] = compilation_cwd
        if solc_args:
            slither_kwargs["solc_args"] = " ".join(solc_args)
    if compilation_cwd:
        os.chdir(compilation_cwd)
    slither = Slither(config.SOL_FILE_PATH, **slither_kwargs)

    analyzer_stats = {
        "contracts_seen": 0,
        "target_contracts": 0,
        "contracts_analyzed": 0,
        "contracts_skipped_interface_abstract_library": 0,
        "contracts_skipped_no_implementation": 0,
        "contracts_skipped_pure_view": 0,
        "contracts_without_native_candidates": 0,
        "sink_agent_calls": 0,
        "taint_agent_calls": 0,
    }
    # slither = Slither(config.SOL_FILE_PATH)

    summary_report = ""
    for contract in slither.contracts:
        analyzer_stats["contracts_seen"] += 1
        if not _is_target_source(contract, config.SOL_FILE_PATH):
            continue
        analyzer_stats["target_contracts"] += 1

        # filter
        if contract.is_interface or contract.is_abstract or contract.is_library:
            analyzer_stats["contracts_skipped_interface_abstract_library"] += 1
            continue
        has_impl = any(f.is_implemented for f in contract.functions_declared)
        if not has_impl:
            analyzer_stats["contracts_skipped_no_implementation"] += 1
            continue

        # skip the contract which all pure or view
        all_pure_or_view = all((f.pure or f.view) for f in contract.functions_declared if f.is_implemented )
        # print(f"contract:{contract.name},pure:{all_pure_or_view}")
        if all_pure_or_view:
            analyzer_stats["contracts_skipped_pure_view"] += 1
            continue

        focus_rules = ""
        vulnerability_report = ""
        tx_report = ""
        cv_graph = BuildCVGraph(contract)
        # cv_graph.display_graph()
        
        for variable_node, function_set in cv_graph.functions_uneffect_critical_variables.items():
            if len(function_set) == 0:
                continue
            for function_node in function_set:
                focus_rules += f"{{Function:{str(function_node)}, Visibility:{function_node.node.visibility}, Explanation:Writes to variable {variable_node} without any access control.}}\n"

        # selfdestruct
        for function, variables in cv_graph.selfdestruct.items():
            
            s = ""
            if len(variables) != 0:
                s += "Affected by variable:"
                for variable in variables:
                    s += str(variable)
                s += ", "

            focus_rules += f"{{Function:{str(function)}, Visibility:{function.visibility}, {s}Explanation:Uses selfdestruct instruction.}}\n"

        # Incorrect usage of tx.origin is directly classified as AC.
        for function in cv_graph.get_tx():
            tx_report += f"{{Function: {str(function)}, Explanation: Uses tx.origin as condition.}}\n"

        for function in cv_graph.get_lowcall():
            focus_rules += f"{{Function:{str(function)}, Visibility:{function.visibility}, Explanation:Uses low level call.}}\n"

        for function in cv_graph.get_assembly():
            focus_rules += f"{{Function:{str(function)}, Visibility:{function.visibility}, Explanation:Uses assembly.}}\n"

        for function in cv_graph.get_transfer():
            focus_rules += f"{{Function:{str(function)}, Visibility:{function.visibility}, Explanation:Transfers Ether or Token.}}\n"

        
        constructor_function_name = ""
        if contract.constructor is not None:
            constructor_function_name = contract.constructor.full_name
            # read_source_code(str(constructor.source_mapping))
            # print(constructor)
            # print(f"  Source mapping:{constructor.source_mapping}")
            # print(f"  Constructor found at line {constructor.source_mapping.lines}")
            # print(constructor.full_name)
            # print(constructor.source_mapping._get_lines_str())
            # print(read_source_code(str(constructor.source_mapping)))

        # read_source_code(str(contract.source_mapping))
        
        
        # continue
        
        if focus_rules == "" and tx_report == "":
            analyzer_stats["contracts_without_native_candidates"] += 1
            continue
        analyzer_stats["contracts_analyzed"] += 1
        analyzer_stats["sink_agent_calls"] += 1
        print("rules:")
        print(focus_rules)
        print(f"=============Contract: {contract.name}")
        
        print("Sink:")

        sink_agent = SinkAgent(focus_rules, constructor_function_name, read_source_code(str(contract.source_mapping)))
        sinks = sink_agent.process()
        # print(sinks)

        if config.No_taint:
            # For No_taint, sinks are vulnerabilities.
            vulnerability_report += sinks + "\n"
        else:
            # sinks exist, taint
            if "no sinks" not in sinks.strip().lower():
                analyzer_stats["taint_agent_calls"] += 1
                taint_agent = TaintAgent(sinks, constructor_function_name, read_source_code(str(contract.source_mapping)))
                vulnerability_report += taint_agent.process() + "\n"
        
        # if vulnerability_report != "":
        #     summary_report = f"contract:{contract.name}\n" + vulnerability_report
    
        print("Report:")
        if tx_report != "":
            tx_report = "--Tx.origin Vulnerability--:\n" + tx_report
        print(vulnerability_report + tx_report)
    
    end_time = time.time()
    analyzer_stats["total_token"] = config.total_token
    analyzer_stats["elapsed_seconds"] = round(end_time - start_time, 3)
    print("ACTAINT_ANALYZER_SUMMARY_JSON=" + json.dumps(analyzer_stats, sort_keys=True))
    print("==============End======================")
    print(f"total time: {end_time - start_time}")
    print(f"total token: {config.total_token}")
    # if summary_report != "":
    #     print("Detect access control vulnerabilities:")
    #     print(summary_report)
    # else:
    #     print("No access control vulnerabilities detected.")