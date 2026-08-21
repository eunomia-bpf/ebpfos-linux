#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate a KOperation proof/native binding table.

Operation files contain semantic data, never machine bytes.  This generator is
the only place that lowers the supported proof and native IR.  Adding an
operation therefore does not add a verifier hook or a handwritten native
fallback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any


TOP_KEYS = {"architecture", "format_version", "operations"}
OP_KEYS = {
    "capabilities",
    "effects",
    "id",
    "name",
    "native_ir",
    "precondition",
    "proof_ir",
    "result",
    "shadow_source",
}
HEX = "0123456789abcdef"


class SpecError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bpf_insn(code: int, dst: int = 0, src: int = 0, off: int = 0,
             imm: int = 0) -> bytes:
    return struct.pack("<BBhi", code, dst | (src << 4), off, imm)


def clear_low_mask(bits: Any, name: str) -> int:
    if not isinstance(bits, int) or bits <= 0 or bits > 31:
        raise SpecError(f"{name}: clear-low-bits must be in [1, 31]")
    return -(1 << bits)


def proof_template(operation: dict[str, Any]) -> tuple[bytes, int]:
    output = bytearray()
    immediate_index: int | None = None
    returned = False
    for instruction in operation["proof_ir"]:
        if not isinstance(instruction, dict) or "op" not in instruction:
            raise SpecError(f"{operation['name']}: malformed proof instruction")
        opcode = instruction["op"]
        if opcode == "load-staged-u64" and set(instruction) == {"op"}:
            if immediate_index is not None or returned:
                raise SpecError(f"{operation['name']}: staged value loaded twice or after return")
            immediate_index = len(output) // 8
            output.extend(bpf_insn(0x18))
            output.extend(bpf_insn(0x00))
        elif opcode == "clear-low-bits" and set(instruction) == {"bits", "op"}:
            if immediate_index is None or returned:
                raise SpecError(f"{operation['name']}: proof transform has no live value")
            output.extend(bpf_insn(0x57, imm=clear_low_mask(
                instruction["bits"], operation["name"])))
        elif opcode == "return" and set(instruction) == {"op"}:
            if immediate_index is None or returned:
                raise SpecError(f"{operation['name']}: invalid proof return")
            output.extend(bpf_insn(0x95))
            returned = True
        else:
            raise SpecError(f"{operation['name']}: unsupported proof opcode {opcode!r}")
    if immediate_index is None or not returned:
        raise SpecError(f"{operation['name']}: proof must load staged state and return")
    return bytes(output), immediate_index


def native_bytes(operation: dict[str, Any]) -> bytes:
    register_reads = {
        # mov %cr3,%rax.  The table is architecture lowering data, not an
        # operation-id/name dispatch table.
        "cr3": bytes.fromhex("0f20d8"),
    }
    # A fixed indirect-entry ABI is part of every generated native image.
    # ENDBR64 is a NOP on non-CET x86-64 CPUs and a required landing pad when
    # kernel IBT is active.
    output = bytearray(bytes.fromhex("f30f1efa"))
    has_value = False
    returned = False
    for instruction in operation["native_ir"]:
        if not isinstance(instruction, dict) or "op" not in instruction:
            raise SpecError(f"{operation['name']}: malformed native instruction")
        opcode = instruction["op"]
        if (opcode == "read-control-register" and
                set(instruction) == {"op", "register"}):
            register = instruction["register"]
            if register not in register_reads or has_value or returned:
                raise SpecError(f"{operation['name']}: unsupported or misplaced control register")
            output.extend(register_reads[register])
            has_value = True
        elif opcode == "clear-low-bits" and set(instruction) == {"bits", "op"}:
            if not has_value or returned:
                raise SpecError(f"{operation['name']}: native transform has no live value")
            mask = clear_low_mask(instruction["bits"], operation["name"])
            output.extend(bytes.fromhex("4825"))  # and imm32-sign-extended,%rax
            output.extend(struct.pack("<i", mask))
        elif opcode == "return" and set(instruction) == {"op"}:
            if not has_value or returned:
                raise SpecError(f"{operation['name']}: invalid native return")
            returned = True
        else:
            raise SpecError(f"{operation['name']}: unsupported native opcode {opcode!r}")
    if not returned:
        raise SpecError(f"{operation['name']}: native program must return")
    return bytes(output)


def check_semantics(operation: dict[str, Any]) -> None:
    precondition = operation["precondition"]
    if (not isinstance(precondition, dict) or set(precondition) != {"left", "right"} or
            precondition["left"] != "staged-u64"):
        raise SpecError(f"{operation['name']}: malformed equivalence precondition")
    right = precondition["right"]
    if (not isinstance(right, dict) or
            set(right) != {"bits", "input", "op"} or
            right["op"] != "clear-low-bits" or
            right["input"] != "hardware.cr3"):
        raise SpecError(f"{operation['name']}: unsupported precondition expression")
    clear_low_mask(right["bits"], operation["name"])
    if operation["shadow_source"] not in {"current-mm-pgd"}:
        raise SpecError(f"{operation['name']}: unsupported shadow source")
    if not isinstance(operation["result"], str) or not operation["result"]:
        raise SpecError(f"{operation['name']}: result contract must be non-empty")


def load_spec(path: Path) -> list[dict[str, Any]]:
    try:
        root = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SpecError(str(error)) from error
    if not isinstance(root, dict) or set(root) != TOP_KEYS:
        raise SpecError("operation file has unknown or missing top-level fields")
    if root["format_version"] != 1 or root["architecture"] != "x86_64":
        raise SpecError("only format 1 x86_64 operation files are supported")
    operations = root["operations"]
    if not isinstance(operations, list) or not operations:
        raise SpecError("operation table must be non-empty")
    ids: set[int] = set()
    names: set[str] = set()
    for operation in operations:
        if not isinstance(operation, dict) or set(operation) != OP_KEYS:
            raise SpecError("operation has unknown or missing fields")
        op_id = operation["id"]
        name = operation["name"]
        if not isinstance(op_id, int) or op_id <= 0 or op_id > 0xFFFFFFFF:
            raise SpecError("operation id is out of range")
        if not isinstance(name, str) or not name or name in names or op_id in ids:
            raise SpecError("operation ids and names must be unique and non-empty")
        for field in ("effects", "capabilities"):
            values = operation[field]
            if (not isinstance(values, list) or not values or
                    values != sorted(set(values)) or
                    not all(isinstance(item, str) and item for item in values)):
                raise SpecError(f"{name}: {field} must be sorted unique strings")
        check_semantics(operation)
        proof_template(operation)
        native_bytes(operation)
        ids.add(op_id)
        names.add(name)
    if operations != sorted(operations, key=lambda item: item["id"]):
        raise SpecError("operations must be sorted by id")
    return operations


def c_bytes(hex_digest: str) -> str:
    if len(hex_digest) != 64 or any(ch not in HEX for ch in hex_digest):
        raise AssertionError(hex_digest)
    return ", ".join(f"0x{hex_digest[index:index + 2]}"
                     for index in range(0, 64, 2))


def symbol(name: str) -> str:
    return "ebpfos_koperation_native_" + "".join(
        character if character.isalnum() else "_" for character in name)


def render(operations: list[dict[str, Any]]) -> tuple[bytes, bytes, bytes]:
    header = [
        "/* Generated by scripts/ebpfos-koperation-gen.py; do not edit. */",
        "#ifndef _EBPFOS_KOPERATION_GENERATED_H",
        "#define _EBPFOS_KOPERATION_GENERATED_H",
        "",
    ]
    assembly = [
        "/* Generated by scripts/ebpfos-koperation-gen.py; do not edit. */",
        "#include <linux/linkage.h>",
        "#include <asm/nospec-branch.h>",
        ".text",
        "",
    ]
    descriptors = []
    certificates = []
    for operation in operations:
        proof, immediate_index = proof_template(operation)
        native = native_bytes(operation)
        semantic_sha = digest(canonical(operation))
        proof_sha = digest(proof)
        native_sha = digest(native)
        equivalence = {
            "native_ir_sha256": digest(canonical(operation["native_ir"])),
            "precondition_sha256": digest(canonical(operation["precondition"])),
            "proof_ir_sha256": digest(canonical(operation["proof_ir"])),
            "result": operation["result"],
        }
        equivalence_sha = digest(canonical(equivalence))
        sym = symbol(operation["name"])
        proof_name = f"ebpfos_koperation_proof_{operation['id']}"
        header.extend([
            f"extern u64 {sym}(void);",
            f"static const struct bpf_insn {proof_name}[] = {{",
        ])
        for offset in range(0, len(proof), 8):
            code, regs, insn_off, imm = struct.unpack("<BBhi", proof[offset:offset + 8])
            header.append(
                "\t{ .code = 0x%02x, .dst_reg = %u, .src_reg = %u, "
                ".off = %d, .imm = %d }," %
                (code, regs & 0x0F, regs >> 4, insn_off, imm))
        header.extend([
            "};",
            "",
        ])
        assembly.extend([
            f"SYM_FUNC_START({sym})",
            "\t.byte " + ", ".join(f"0x{byte:02x}" for byte in native),
            f".L{sym}_body_end:",
            "\tRET",
            f"SYM_FUNC_END({sym})",
            "",
        ])
        descriptors.append(
            "\t{\n"
            f"\t\t.operation_id = {operation['id']}U,\n"
            f"\t\t.proof_insns = {proof_name},\n"
            f"\t\t.proof_insn_count = ARRAY_SIZE({proof_name}),\n"
            f"\t\t.proof_imm64_insn = {immediate_index}U,\n"
            "\t\t.shadow_source = EBPFOS_KOPERATION_SHADOW_CURRENT_MM_PGD,\n"
            f"\t\t.native_emit = {sym},\n"
            f"\t\t.native_body_size = {len(native)}U,\n"
            f"\t\t.semantic_sha256 = {{ {c_bytes(semantic_sha)} }},\n"
            f"\t\t.proof_template_sha256 = {{ {c_bytes(proof_sha)} }},\n"
            f"\t\t.native_sha256 = {{ {c_bytes(native_sha)} }},\n"
            f"\t\t.equivalence_sha256 = {{ {c_bytes(equivalence_sha)} }},\n"
            "\t},")
        certificates.append({
            "architecture": "x86_64",
            "capabilities": operation["capabilities"],
            "effects": operation["effects"],
            "equivalence_obligation": equivalence,
            "equivalence_sha256": equivalence_sha,
            "execution_proof_complete": False,
            "equivalence_status": "runtime-required",
            "generator_proof_status": "bound-unproved",
            "id": operation["id"],
            "name": operation["name"],
            "native_bytes_sha256": native_sha,
            "native_body_size": len(native),
            "native_source": "generated-from-native-ir",
            "return_abi": "kernel-rethunk",
            "proof_template_sha256": proof_sha,
            "semantic_sha256": semantic_sha,
            "verifier_admission": "runtime-required",
        })
    header.extend([
        "static const struct ebpfos_koperation_descriptor",
        "ebpfos_koperation_descriptors[] = {",
        *descriptors,
        "};",
        "",
        "#endif",
        "",
    ])
    certificate = {
        "architecture": "x86_64",
        "execution_proof_complete": False,
        "format_version": 1,
        "native_fallbacks": 0,
        "operations": certificates,
    }
    return ("\n".join(header).encode(), "\n".join(assembly).encode(),
            canonical(certificate))


def write_or_check(path: Path, data: bytes, check: bool) -> None:
    if check:
        try:
            actual = path.read_bytes()
        except OSError as error:
            raise SpecError(str(error)) from error
        if actual != data:
            raise SpecError(f"generated artifact mismatch: {path}")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--header", required=True, type=Path)
    parser.add_argument("--assembly", required=True, type=Path)
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        outputs = render(load_spec(args.spec))
        for path, data in zip(
                (args.header, args.assembly, args.certificate), outputs):
            write_or_check(path, data, args.check)
    except SpecError as error:
        print(f"ebpfos-koperation-gen: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
