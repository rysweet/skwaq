# Ghidra headless post-script: extract functions, strings, imports, and decompiled code.
# Usage: analyzeHeadless <project> <name> -import <binary> -postScript extract_analysis.py <output.json>
#
# Output: JSON file with functions (name, address, decompiled, calls, parameters),
#         strings, and imports.
#
# @category Skwaq
# @author skwaq

import json
import sys

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def get_output_path():
    """Get output file path from script arguments."""
    args = getScriptArgs()
    if args and len(args) > 0:
        return args[0]
    # Default fallback
    name = currentProgram.getName()
    return "/tmp/skwaq_analysis_{}.json".format(name.replace("/", "_"))

def extract_functions(decomp):
    """Extract all functions with decompiled code."""
    monitor = ConsoleTaskMonitor()
    fm = currentProgram.getFunctionManager()
    functions = []

    for func in fm.getFunctions(True):
        entry = {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": int(func.getBody().getNumAddresses()),
            "decompiled": None,
            "calls": [],
            "called_by": [],
            "parameter_count": func.getParameterCount(),
        }

        # Decompile
        try:
            results = decomp.decompileFunction(func, 30, monitor)
            if results and results.getDecompiledFunction():
                c_code = results.getDecompiledFunction().getC()
                if c_code:
                    entry["decompiled"] = c_code
        except Exception as e:
            entry["decompiled"] = "// Decompilation failed: {}".format(str(e))

        # Get calls (references from this function)
        for ref in func.getBody().getAddresses(True):
            pass  # Would need reference manager - simplified for now

        # Get called functions
        called = func.getCalledFunctions(monitor)
        if called:
            entry["calls"] = [str(f.getEntryPoint()) for f in called]

        # Get calling functions
        calling = func.getCallingFunctions(monitor)
        if calling:
            entry["called_by"] = [str(f.getEntryPoint()) for f in calling]

        functions.append(entry)

    return functions

def extract_strings():
    """Extract defined strings from the binary."""
    strings = []
    data_iter = currentProgram.getListing().getDefinedData(True)

    count = 0
    for data in data_iter:
        if count >= 10000:
            break
        dt = data.getDataType()
        if dt and "string" in dt.getName().lower():
            try:
                val = data.getValue()
                if val and len(str(val)) >= 4:
                    strings.append({
                        "value": str(val),
                        "offset": str(data.getAddress()),
                        "encoding": "utf8",
                    })
                    count += 1
            except:
                pass

    return strings

def extract_imports():
    """Extract imported functions."""
    imports = []
    sym_table = currentProgram.getSymbolTable()

    for sym in sym_table.getExternalSymbols():
        imports.append({
            "name": sym.getName(),
            "library": str(sym.getParentNamespace()),
        })

    return imports

def main():
    output_path = get_output_path()

    # Set up decompiler
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    println("Skwaq: Extracting analysis data...")

    functions = extract_functions(decomp)
    println("Skwaq: Extracted {} functions".format(len(functions)))

    strings = extract_strings()
    println("Skwaq: Extracted {} strings".format(len(strings)))

    imports = extract_imports()
    println("Skwaq: Extracted {} imports".format(len(imports)))

    decomp.dispose()

    # Write output
    result = {
        "functions": functions,
        "strings": strings,
        "imports": imports,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    println("Skwaq: Analysis written to {}".format(output_path))

main()
