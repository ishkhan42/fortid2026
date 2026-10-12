#!/usr/bin/env python3
"""Fingerprint direct-call structure and XOR/NOT immediates in x86-64 ELF code.

This is a lightweight structural analysis aid, not a decompiler or proof of
semantic equivalence. It processes local ELF files only.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_OP_IMM, CS_OP_MEM
from elftools.elf.elffile import ELFFile


def digest(value: object) -> str:
    packed = json.dumps(value, separators=(",", ":"), sort_keys=False).encode()
    return hashlib.sha256(packed).hexdigest()


def counter_items(counter: Counter[int]) -> list[list[int]]:
    return [[int(value), int(count)] for value, count in sorted(counter.items())]


def xor_values(values: Counter[int]) -> int:
    result = 0
    for value, count in values.items():
        if count & 1:
            result ^= value
    return result


def collect_functions(binary: Path, symbol_pattern: re.Pattern[str]):
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        text = elf.get_section_by_name(".text")
        symtab = elf.get_section_by_name(".symtab")
        if text is None or symtab is None:
            raise ValueError("ELF must contain .text and .symtab sections")
        if elf.elfclass != 64 or elf["e_machine"] != "EM_X86_64":
            raise ValueError("only ELF64 x86-64 binaries are supported")
        text_addr = int(text["sh_addr"])
        text_data = text.data()
        functions = {}
        for symbol in symtab.iter_symbols():
            if symbol["st_info"]["type"] != "STT_FUNC":
                continue
            name = symbol.name
            if not name or not symbol_pattern.search(name):
                continue
            address = int(symbol["st_value"])
            size = int(symbol["st_size"])
            offset = address - text_addr
            if size == 0 or offset < 0 or offset + size > len(text_data):
                continue
            functions.setdefault(
                address,
                {"addr": address, "size": size, "name": name,
                 "local": [], "calls": []},
            )

        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        disassembler.detail = True
        for address, function in functions.items():
            offset = address - text_addr
            code = text_data[offset:offset + function["size"]]
            for instruction in disassembler.disasm(code, address):
                operands = instruction.operands
                if (instruction.mnemonic == "xor" and len(operands) == 2
                        and operands[0].type == CS_OP_MEM
                        and operands[1].type == CS_OP_IMM):
                    function["local"].append(int(operands[1].imm) & 0xFF)
                elif (instruction.mnemonic == "not" and len(operands) == 1
                      and operands[0].type == CS_OP_MEM):
                    function["local"].append(0xFF)
                if (instruction.group(CS_GRP_CALL) and operands
                        and operands[0].type == CS_OP_IMM):
                    target = int(operands[0].imm)
                    if target in functions:
                        function["calls"].append(target)
    return functions


def summarize(functions: dict[int, dict]):
    memo = {}
    active = set()

    def visit(address: int):
        if address in memo:
            return memo[address]
        if address in active:
            raise ValueError(f"recursive direct-call graph at {address:#x}")
        active.add(address)
        function = functions[address]
        children = [visit(child) for child in function["calls"]]
        arity = len(children)
        shape_raw = digest([arity, [child["shape_raw"] for child in children]])
        shape_sorted = digest(
            [arity, sorted(child["shape_sorted"] for child in children)]
        )

        if children:
            leaves: Counter[int] = Counter()
            for child in children:
                leaves.update(child["leaves"])
        else:
            leaves = Counter(function["local"])
        immediates = Counter(function["local"])
        for child in children:
            immediates.update(child["immediates"])

        leaf_xor = xor_values(leaves)
        subtree_xor = xor_values(immediates)
        leaf_repr = counter_items(leaves)
        all_repr = counter_items(immediates)
        result = {
            "shape_raw": shape_raw,
            "shape_sorted": shape_sorted,
            "fingerprint_raw": digest([arity, leaf_repr, leaf_xor, shape_raw]),
            "fingerprint_sorted": digest([arity, leaf_repr, leaf_xor, shape_sorted]),
            "semantic_raw": digest([arity, all_repr, subtree_xor, shape_raw]),
            "semantic_sorted": digest([arity, all_repr, subtree_xor, shape_sorted]),
            "leaves": leaves,
            "leaf_xor": leaf_xor,
            "immediates": immediates,
            "subtree_xor": subtree_xor,
            "node_count": 1 + sum(child["node_count"] for child in children),
            "arity": arity,
        }
        memo[address] = result
        active.remove(address)
        function.update({
            key: value for key, value in result.items()
            if key not in ("leaves", "immediates")
        })
        return result

    for address in functions:
        visit(address)
    return memo


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="local ELF64 x86-64 input")
    parser.add_argument(
        "--symbol-regex", default=".*",
        help="select function names with this regular expression (default: all)",
    )
    parser.add_argument(
        "--output", type=Path,
        help="output JSON path (default: <binary>.fingerprints.json)",
    )
    args = parser.parse_args()
    try:
        symbol_pattern = re.compile(args.symbol_regex)
        functions = collect_functions(args.binary, symbol_pattern)
        if not functions:
            parser.error("no matching, sized function symbols found in .text")
        memo = summarize(functions)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"functions={len(functions)} graph_functions_with_code={len(memo)}")
    for key in (
        "shape_raw", "shape_sorted", "fingerprint_raw", "fingerprint_sorted",
        "semantic_raw", "semantic_sorted",
    ):
        counts = Counter(function[key] for function in functions.values())
        repeated = sum(count > 1 for count in counts.values())
        max_group = max(counts.values()) if counts else 0
        print(
            f"DUP {key}: unique={len(counts)} repeated_groups={repeated} "
            f"max_group={max_group}"
        )

    records = []
    for address, function in sorted(functions.items()):
        info = memo[address]
        records.append({
            "addr": f"{address:#x}",
            "name": function["name"],
            "arity": function["arity"],
            "local_memory_immediates": function["local"],
            "calls": [f"{target:#x}" for target in function["calls"]],
            "leaf_multiset": counter_items(info["leaves"]),
            "leaf_xor": info["leaf_xor"],
            "subtree_xor": info["subtree_xor"],
            "node_count": info["node_count"],
            "shape_raw": info["shape_raw"],
            "shape_sorted": info["shape_sorted"],
            "fingerprint_raw": info["fingerprint_raw"],
            "fingerprint_sorted": info["fingerprint_sorted"],
            "semantic_raw": info["semantic_raw"],
            "semantic_sorted": info["semantic_sorted"],
        })

    output = args.output or Path(f"{args.binary}.fingerprints.json")
    output.write_text(json.dumps(records, separators=(",", ":")), encoding="utf-8")
    print(f"WROTE {output} records={len(records)}")


if __name__ == "__main__":
    main()
