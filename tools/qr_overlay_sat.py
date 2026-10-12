#!/usr/bin/env python3
"""Search for a jointly valid overlay of two version-1 alphanumeric QR codes.

The model permits bounded QR error-correction damage and supports a caller-
selected reflection/rotation relationship. It is a specialized SAT analysis
tool, not a general QR encoder; a bounded search that finds no model is not a
proof that no overlay exists.
"""

from __future__ import annotations

import argparse
import itertools
from pathlib import Path
import re

import numpy as np
import qrcode
from qrcode import base as qr_base
from qrcode import util as qr_util
from qrcode.constants import (
    ERROR_CORRECT_H,
    ERROR_CORRECT_L,
    ERROR_CORRECT_M,
    ERROR_CORRECT_Q,
)
from pysat.card import CardEnc, EncType
from pysat.formula import IDPool
from pysat.solvers import CryptoMinisat

_SIZE = 21
_ERROR_LEVELS = {
    "L": ERROR_CORRECT_L,
    "M": ERROR_CORRECT_M,
    "Q": ERROR_CORRECT_Q,
    "H": ERROR_CORRECT_H,
}
_ALPHA_NUMERIC = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")
_BASIS_CACHE = {}


def qr_layout(error_level: int, mask: int):
    qr = qrcode.QRCode(version=1, error_correction=error_level, box_size=1, border=0)
    qr.modules_count = _SIZE
    if 1 not in qrcode.main.precomputed_qr_blanks:
        qr.modules = [[None] * _SIZE for _ in range(_SIZE)]
        qr.setup_position_probe_pattern(0, 0)
        qr.setup_position_probe_pattern(_SIZE - 7, 0)
        qr.setup_position_probe_pattern(0, _SIZE - 7)
        qr.setup_position_adjust_pattern()
        qr.setup_timing_pattern()
        qrcode.main.precomputed_qr_blanks[1] = qrcode.main.copy_2d_array(qr.modules)
    qr.modules = qrcode.main.copy_2d_array(qrcode.main.precomputed_qr_blanks[1])
    before = [[value is None for value in row] for row in qr.modules]
    qr.setup_type_info(True, mask)
    with_format = qr.modules
    format_cells = {
        (row, column)
        for row in range(_SIZE)
        for column in range(_SIZE)
        if before[row][column] and with_format[row][column] is not None
    }
    data_cells = [[value is None for value in row] for row in with_format]
    positions = []
    direction = -1
    row = _SIZE - 1
    for right_column in range(_SIZE - 1, 0, -2):
        column = right_column - 1 if right_column <= 6 else right_column
        while True:
            for current_column in (column, column - 1):
                if data_cells[row][current_column]:
                    positions.append((row, current_column))
            row += direction
            if row < 0 or row >= _SIZE:
                row -= direction
                direction = -direction
                break
    function_cells = {
        (row, column)
        for row in range(_SIZE)
        for column in range(_SIZE)
        if not before[row][column]
    }
    return positions, format_cells, function_cells


def alphanumeric_data(text: str, error_level: int):
    data_count = qr_base.rs_blocks(1, error_level)[0].data_count
    buffer = qr_util.BitBuffer()
    data = qr_util.QRData(text, mode=qr_util.MODE_ALPHA_NUM)
    buffer.put(data.mode, 4)
    buffer.put(len(text), 9)
    data.write(buffer)
    buffer.put(0, 4)
    prefix_length = len(buffer)
    if prefix_length > data_count * 8:
        raise ValueError("message does not fit in a version-1 QR code at this ECC level")
    while len(buffer) < data_count * 8:
        buffer.put(0, 1)
    return bytes(buffer.buffer), prefix_length, data_count


def codewords_from_raw(raw: bytes, error_level: int) -> bytes:
    buffer = qr_util.BitBuffer()
    for value in raw:
        buffer.put(value, 8)
    return qr_util.create_bytes(buffer, qr_base.rs_blocks(1, error_level))


def rs_basis(error_level: int):
    if error_level in _BASIS_CACHE:
        return _BASIS_CACHE[error_level]
    data_count = qr_base.rs_blocks(1, error_level)[0].data_count
    basis = []
    for bit_index in range(data_count * 8):
        raw = bytearray(data_count)
        raw[bit_index // 8] = 1 << (7 - (bit_index % 8))
        basis.append(codewords_from_raw(bytes(raw), error_level))
    _BASIS_CACHE[error_level] = basis
    return basis


def message_description(text: str, error_level: int, mask: int):
    positions, format_cells, function_cells = qr_layout(error_level, mask)
    raw, prefix_length, data_count = alphanumeric_data(text, error_level)
    base_codewords = codewords_from_raw(raw, error_level)
    qr = qrcode.QRCode(version=1, error_correction=error_level, box_size=1, border=0)
    qr.data_cache = base_codewords
    qr.makeImpl(False, mask)
    matrix = np.array(qr.modules, dtype=np.uint8)

    free_bits = list(range(prefix_length, data_count * 8))
    basis = rs_basis(error_level)
    codeword_bit = {position: (index // 8, index % 8)
                    for index, position in enumerate(positions)}
    terms = {}
    for position in positions:
        codeword, bit = codeword_bit[position]
        toggles = []
        for free_index, raw_bit in enumerate(free_bits):
            if (basis[raw_bit][codeword] >> (7 - bit)) & 1:
                toggles.append(free_index)
        terms[position] = (tuple(toggles), bool(matrix[position]))
    return {
        "text": text,
        "error_level": error_level,
        "mask": mask,
        "positions": positions,
        "format_cells": format_cells,
        "function_cells": function_cells,
        "codeword_bit": codeword_bit,
        "terms": terms,
        "matrix": matrix,
        "data_count": data_count,
        "total_codewords": len(base_codewords),
        "free_bit_count": len(free_bits),
    }


def format_groups():
    first = ({(index, 8) for index in list(range(6)) + [7, 8]}
             | {(8, 7)} | {(8, column) for column in range(6)})
    second = ({(row, 8) for row in range(14, 21)}
              | {(8, column) for column in range(13, 21)})
    return [first, second]


def coordinate_map(transform):
    mirror, rotations = transform
    mapped = {}
    for row in range(_SIZE):
        for column in range(_SIZE):
            target_row, target_column = row, (_SIZE - 1 - column if mirror else column)
            for _ in range(rotations):
                target_row, target_column = _SIZE - 1 - target_column, target_row
            mapped[(row, column)] = (target_row, target_column)
    return mapped


def add_at_most(solver, literals, bound, variable_pool):
    if bound < 0:
        solver.add_clause([])
        return
    if len(literals) <= bound:
        return
    encoding = CardEnc.atmost(
        lits=literals, bound=bound, vpool=variable_pool, encoding=EncType.seqcounter
    )
    for clause in encoding.clauses:
        solver.add_clause(clause)


def feasible_format_choices(left, right, transform, anchors):
    mapping = coordinate_map(transform)
    inverse = {target: source for source, target in mapping.items()}
    anchor_cells = set(anchors)
    fixed_left = left["function_cells"] | anchor_cells
    fixed_right = {inverse[position] for position in right["function_cells"] | anchor_cells}
    forced = {}
    for row in range(_SIZE):
        for column in range(_SIZE):
            position = (row, column)
            values = []
            if position in fixed_left:
                values.append(bool(left["matrix"][position]))
            if position in fixed_right:
                values.append(bool(right["matrix"][mapping[position]]))
            if values and any(value != values[0] for value in values):
                return []
            if values:
                forced[position] = values[0]

    choices = []
    left_groups = format_groups()
    right_groups = [{inverse[position] for position in group} for group in left_groups]
    for left_group_index, right_group_index in itertools.product(range(2), repeat=2):
        left_group = left_groups[left_group_index]
        right_group = right_groups[right_group_index]
        base_left = base_right = disagreements = 0
        for position in left_group | right_group:
            in_left = position in left_group
            in_right = position in right_group
            left_value = bool(left["matrix"][position]) if in_left else None
            right_value = bool(right["matrix"][mapping[position]]) if in_right else None
            if position in forced:
                if in_left and forced[position] != left_value:
                    base_left += 1
                if in_right and forced[position] != right_value:
                    base_right += 1
            elif in_left and in_right and left_value != right_value:
                disagreements += 1
        lower = max(0, disagreements - (3 - base_right))
        upper = min(disagreements, 3 - base_left)
        if base_left <= 3 and base_right <= 3 and lower <= upper:
            choices.append((left_group_index, right_group_index))
    return choices


def solve_pair(left, right, transform, time_budget, conflict_budget, anchors):
    mapping = coordinate_map(transform)
    inverse = {target: source for source, target in mapping.items()}
    left_data = set(left["positions"])
    right_data_display = {inverse[position] for position in right["positions"]}
    anchor_cells = set(anchors)
    fixed_left = left["function_cells"] | anchor_cells
    fixed_right_display = {
        inverse[position] for position in right["function_cells"] | anchor_cells
    }
    left_format_groups = format_groups()
    right_format_groups = [
        {inverse[position] for position in group} for group in format_groups()
    ]
    format_cells = set().union(*left_format_groups) | set().union(*right_format_groups)
    forced = {}
    free_format_cells = {}
    for row in range(_SIZE):
        for column in range(_SIZE):
            position = (row, column)
            values = []
            if position in fixed_left:
                values.append(bool(left["matrix"][position]))
            if position in fixed_right_display:
                values.append(bool(right["matrix"][mapping[position]]))
            if values and any(value != values[0] for value in values):
                return None, ("fixed-cell-conflict", position)
            if values:
                forced[position] = values[0]
            elif position in format_cells:
                free_format_cells[position] = None

    for position in left_data ^ right_data_display:
        if position not in forced and position not in free_format_cells:
            return None, ("unclassified-cell", position)

    choices = feasible_format_choices(left, right, transform, anchors)
    timed_out = False
    for left_group_index, right_group_index in choices:
        variable_pool = IDPool()
        solver = CryptoMinisat()
        try:
            def new_variable(key):
                return variable_pool.id(key)

            left_bits = [new_variable(("left-bit", index))
                         for index in range(left["free_bit_count"])]
            right_bits = [new_variable(("right-bit", index))
                          for index in range(right["free_bit_count"])]
            format_variables = {
                position: new_variable(("format", position))
                for position in free_format_cells
            }
            left_errors = [new_variable(("left-error", index))
                           for index in range(left["total_codewords"])]
            right_errors = [new_variable(("right-error", index))
                            for index in range(right["total_codewords"])]

            def expression(description, position, side):
                indices, parity = description["terms"][position]
                variables = left_bits if side == "left" else right_bits
                return [variables[index] for index in indices], parity

            def pair_expression(position):
                if position in forced:
                    return [], forced[position]
                if position in format_variables:
                    return [format_variables[position]], False
                return None

            auxiliary_index = 0

            def difference(first, second):
                nonlocal auxiliary_index
                variables = list(first[0])
                parity = bool(first[1])
                for variable in second[0]:
                    if variable in variables:
                        variables.remove(variable)
                    else:
                        variables.append(variable)
                parity ^= bool(second[1])
                if not variables:
                    return int(parity)
                result = new_variable(("xor", auxiliary_index))
                auxiliary_index += 1
                solver.add_xor_clause(variables + [result], value=parity)
                return result

            for row, column in left["positions"]:
                position = (row, column)
                right_position = mapping[position]
                left_error = left_errors[left["codeword_bit"][position][0]]
                if position in right_data_display:
                    right_error = right_errors[right["codeword_bit"][right_position][0]]
                    delta = difference(
                        expression(left, position, "left"),
                        expression(right, right_position, "right"),
                    )
                    if delta == 1:
                        solver.add_clause([left_error, right_error])
                    elif delta > 1:
                        solver.add_clause([-delta, left_error, right_error])
                else:
                    paired = pair_expression(position)
                    if paired is None:
                        return None, ("missing-left-cell", position)
                    delta = difference(expression(left, position, "left"), paired)
                    if delta == 1:
                        solver.add_clause([left_error])
                    elif delta > 1:
                        solver.add_clause([-delta, left_error])

            for row, column in right["positions"]:
                position = inverse[(row, column)]
                if position in left_data:
                    continue
                right_error = right_errors[right["codeword_bit"][(row, column)][0]]
                paired = pair_expression(position)
                if paired is None:
                    return None, ("missing-right-cell", position)
                delta = difference(expression(right, (row, column), "right"), paired)
                if delta == 1:
                    solver.add_clause([right_error])
                elif delta > 1:
                    solver.add_clause([-delta, right_error])

            left_error_budget = (
                left["total_codewords"] - left["data_count"]
            ) // 2
            right_error_budget = (
                right["total_codewords"] - right["data_count"]
            ) // 2
            add_at_most(solver, left_errors, left_error_budget, variable_pool)
            add_at_most(solver, right_errors, right_error_budget, variable_pool)

            def add_format_constraint(group, description, is_right):
                literals = []
                fixed_errors = 0
                for position in group:
                    matrix_position = mapping[position] if is_right else position
                    wanted = bool(description["matrix"][matrix_position])
                    if position in forced:
                        if forced[position] != wanted:
                            fixed_errors += 1
                    else:
                        variable = format_variables[position]
                        literals.append(-variable if wanted else variable)
                add_at_most(solver, literals, 3 - fixed_errors, variable_pool)

            add_format_constraint(
                left_format_groups[left_group_index], left, False
            )
            add_format_constraint(
                right_format_groups[right_group_index], right, True
            )
            if time_budget is not None:
                solver.conf_budget(conflict_budget)
                solver.time_budget(time_budget)
            answer = solver.solve_limited()
            if answer is None:
                timed_out = True
                continue
            if not answer:
                continue

            model = {literal for literal in solver.get_model() if literal > 0}

            def value_of(variable):
                return variable in model

            left_suffix = [int(value_of(variable)) for variable in left_bits]
            right_suffix = [int(value_of(variable)) for variable in right_bits]

            def evaluate_expression(description, position, side):
                indices, parity = description["terms"][position]
                variables = left_bits if side == "left" else right_bits
                return bool(parity ^ (sum(value_of(variables[index]) for index in indices) % 2))

            output = np.zeros((_SIZE, _SIZE), dtype=np.uint8)
            for row in range(_SIZE):
                for column in range(_SIZE):
                    position = (row, column)
                    right_position = mapping[position]
                    if position in forced:
                        value = forced[position]
                    elif position in format_variables:
                        value = value_of(format_variables[position])
                    elif position in left_data and position in right_data_display:
                        left_error = value_of(left_errors[left["codeword_bit"][position][0]])
                        right_error = value_of(right_errors[right["codeword_bit"][right_position][0]])
                        value = (
                            evaluate_expression(left, position, "left")
                            if not left_error or right_error
                            else evaluate_expression(right, right_position, "right")
                        )
                    elif position in left_data:
                        value = evaluate_expression(left, position, "left")
                    elif position in right_data_display:
                        value = evaluate_expression(right, right_position, "right")
                    else:
                        value = False
                    output[position] = int(value)

            active_errors = []
            for description, is_right in ((left, False), (right, True)):
                bad_codewords = set()
                for row, column in description["positions"]:
                    position = inverse[(row, column)] if is_right else (row, column)
                    side = "right" if is_right else "left"
                    wanted = evaluate_expression(description, (row, column), side)
                    if bool(output[position]) != wanted:
                        bad_codewords.add(description["codeword_bit"][(row, column)][0])
                active_errors.append(len(bad_codewords))
            return output, (
                "sat", transform, left_group_index, right_group_index,
                active_errors, left_error_budget, right_error_budget,
                int(output.sum()), left_suffix, right_suffix,
            )
        finally:
            solver.delete()
    return None, ("unknown" if timed_out else "unsat", transform)


def parse_anchor(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"([0-9]+),([0-9]+)", value)
    if match is None:
        raise argparse.ArgumentTypeError("anchor must be ROW,COLUMN")
    row, column = map(int, match.groups())
    if not (0 <= row < _SIZE and 0 <= column < _SIZE):
        raise argparse.ArgumentTypeError("anchor coordinates must be in 0..20")
    return row, column


def search_overlay(left_text, right_text, left_level, right_level,
                   transforms, time_budget, conflict_budget, anchors):
    left_by_mask = {
        mask: message_description(left_text, left_level, mask) for mask in range(8)
    }
    right_by_mask = {
        mask: message_description(right_text, right_level, mask) for mask in range(8)
    }
    for transform in transforms:
        for left_mask in range(8):
            for right_mask in range(8):
                matrix, info = solve_pair(
                    left_by_mask[left_mask],
                    right_by_mask[right_mask],
                    transform,
                    time_budget,
                    conflict_budget,
                    anchors,
                )
                print(
                    f"mask_left={left_mask} mask_right={right_mask} "
                    f"transform={transform} result={info[0]}",
                    flush=True,
                )
                if matrix is not None:
                    return matrix, info
    return None, None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", help="first uppercase alphanumeric QR message")
    parser.add_argument("right", help="second uppercase alphanumeric QR message")
    parser.add_argument("--output", type=Path, required=True, help="output .npz path")
    parser.add_argument("--left-ecc", choices=_ERROR_LEVELS, default="H")
    parser.add_argument("--right-ecc", choices=_ERROR_LEVELS, default="H")
    parser.add_argument(
        "--reflection", choices=("both", "yes", "no"), default="both",
        help="try mirrored, unmirrored, or both orientations (default: both)",
    )
    parser.add_argument(
        "--rotations", nargs="+", type=int, choices=range(4), default=[0, 1, 2, 3],
        help="clockwise quarter-turns to try (default: all four)",
    )
    parser.add_argument(
        "--anchor", action="append", type=parse_anchor, default=[],
        help="optional corresponding module coordinate ROW,COLUMN; repeatable",
    )
    parser.add_argument(
        "--time-budget", type=float, default=3.0,
        help="seconds per solver call (default: 3)",
    )
    parser.add_argument(
        "--conflict-budget", type=int, default=10_000_000,
        help="conflicts per solver call (default: 10000000)",
    )
    args = parser.parse_args()

    if args.output.suffix.lower() != ".npz":
        parser.error("--output must end in .npz")
    if args.time_budget <= 0 or args.conflict_budget <= 0:
        parser.error("time and conflict budgets must be positive")
    for text in (args.left, args.right):
        if not text or any(character not in _ALPHA_NUMERIC for character in text):
            parser.error("messages must use uppercase QR alphanumeric characters only")

    mirror_values = (False, True) if args.reflection == "both" else (args.reflection == "yes",)
    transforms = list(dict.fromkeys(
        (mirror, rotation)
        for mirror in mirror_values
        for rotation in args.rotations
    ))
    matrix, info = search_overlay(
        args.left,
        args.right,
        _ERROR_LEVELS[args.left_ecc],
        _ERROR_LEVELS[args.right_ecc],
        transforms,
        args.time_budget,
        args.conflict_budget,
        args.anchor,
    )
    if matrix is None:
        print(
            "no model found within the bounded search; this is not proof "
            "that no overlay exists",
            flush=True,
        )
        return 2

    np.savez(
        args.output,
        matrix=matrix,
        left_suffix=np.asarray(info[-2], dtype=np.uint8),
        right_suffix=np.asarray(info[-1], dtype=np.uint8),
        left=args.left,
        right=args.right,
        transform=np.asarray(info[1], dtype=np.int8),
    )
    print(f"saved={args.output} dark_modules={int(matrix.sum())}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
