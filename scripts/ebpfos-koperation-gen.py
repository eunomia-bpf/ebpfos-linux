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
    "postcondition",
    "precondition",
    "proof_ir",
    "result",
    "shadow_source",
}
HEX = "0123456789abcdef"
CONTROL_REGISTERS = {
    "cr3": {
        "max_writes": 1,
        "normalize_bits": 12,
        "payload_id": 3,
        "read": bytes.fromhex("0f20d8"),
        "read_effects": ["page_table.root.observe"],
        "read_post_state": "result-u64",
        "readback_required": True,
        "shadow_constant": "EBPFOS_KOPERATION_SHADOW_CURRENT_MM_PGD",
        "shadow_sources": {"current-mm-pgd"},
        "write": bytes.fromhex("0f22d8"),
        "write_effects": [
            "page_table.root.preserve",
            "tlb.current-hardware-cr3-context.non-global.invalidate",
        ],
        "write_observations": [
            "cpu.before-after-equal",
            "cr3.write.noflush-bit-clear",
            "cr4.pcide-runtime-value",
            "cr4.pge-runtime-value",
            "executor.preemption-disabled",
            "linux.flush-tlb-local.not-claimed",
            "pti.user-companion-asid.not-modeled",
        ],
        "write_post_state": "hardware.cr3.root-after",
        "write_source": "register-before",
    },
    "cr4": {
        "max_writes": 0,
        "normalize_bits": 0,
        "payload_id": 4,
        "read": bytes.fromhex("0f20e0"),
        "read_effects": ["cpu.control-state.observe"],
        "read_post_state": "result-u64",
        "readback_required": False,
        "shadow_constant": "EBPFOS_KOPERATION_SHADOW_CURRENT_CR4",
        "shadow_sources": {"current-cr4"},
        "write": b"",
        "write_effects": [],
        "write_observations": [],
        "write_post_state": "hardware.cr4.after",
        "write_source": "register-before",
    },
}

CONTROL_ACTIONS = {
    "reload": 1,
    "observe": 2,
}


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
    if not isinstance(bits, int) or bits < 0 or bits > 31:
        raise SpecError(f"{name}: clear-low-bits must be in [0, 31]")
    return -(1 << bits)


def effect_tag(effect: str) -> int:
    return int.from_bytes(hashlib.sha256(effect.encode()).digest()[:4], "little") & 0x7fffffff


def proof_effect_xor(operation: dict[str, Any]) -> int:
    result = 0
    for effect in operation["effects"]:
        result ^= effect_tag(effect)
    return result


def proof_template(operation: dict[str, Any]) -> tuple[bytes, int]:
    output = bytearray()
    immediate_index: int | None = None
    committed_effects: list[str] = []
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
        elif opcode == "commit-effect" and set(instruction) == {"effect", "op"}:
            effect = instruction["effect"]
            if (immediate_index is None or returned or
                    not isinstance(effect, str) or not effect):
                raise SpecError(f"{operation['name']}: invalid proof effect commitment")
            committed_effects.append(effect)
            output.extend(bpf_insn(0xa7, imm=effect_tag(effect)))
        elif opcode == "return" and set(instruction) == {"op"}:
            if immediate_index is None or returned:
                raise SpecError(f"{operation['name']}: invalid proof return")
            output.extend(bpf_insn(0x95))
            returned = True
        else:
            raise SpecError(f"{operation['name']}: unsupported proof opcode {opcode!r}")
    if immediate_index is None or not returned:
        raise SpecError(f"{operation['name']}: proof must load staged state and return")
    if committed_effects != operation["effects"]:
        raise SpecError(f"{operation['name']}: proof effects do not match declared effects")
    return bytes(output), immediate_index


def expression_text(expression: tuple[Any, ...]) -> str:
    if expression[0] == "register-before":
        return f"{expression[1]}-before-raw"
    if expression[0] == "register-after":
        return f"{expression[1]}-after-raw"
    if expression[0] == "clear-low-bits":
        return f"normalize{expression[1]}({expression_text(expression[2])})"
    raise AssertionError(expression)


def native_lower(operation: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    # A fixed indirect-entry ABI is part of every generated native image.
    # ENDBR64 is a NOP on non-CET x86-64 CPUs and a required landing pad when
    # kernel IBT is active.
    output = bytearray(bytes.fromhex("f30f1efa"))
    value: tuple[Any, ...] | None = None
    register_state: dict[str, tuple[Any, ...]] = {}
    writes: list[tuple[str, tuple[Any, ...]]] = []
    read_after_write: set[str] = set()
    events: list[dict[str, Any]] = []
    returned = False
    for instruction in operation["native_ir"]:
        if not isinstance(instruction, dict) or "op" not in instruction:
            raise SpecError(f"{operation['name']}: malformed native instruction")
        opcode = instruction["op"]
        if (opcode == "read-control-register" and
                set(instruction) == {"op", "register"}):
            register = instruction["register"]
            if register not in CONTROL_REGISTERS or returned:
                raise SpecError(f"{operation['name']}: unsupported or misplaced control register")
            output.extend(CONTROL_REGISTERS[register]["read"])
            if register in register_state:
                value = ("register-after", register, register_state[register])
                read_after_write.add(register)
            else:
                value = ("register-before", register)
            events.append({
                "op": "read-control-register",
                "register": register,
                "value": expression_text(value),
            })
        elif (opcode == "write-control-register" and
              set(instruction) == {"op", "register", "source"}):
            register = instruction["register"]
            if (register not in CONTROL_REGISTERS or
                    instruction["source"] != "value" or
                    value is None or returned):
                raise SpecError(f"{operation['name']}: unsupported or misplaced control-register write")
            output.extend(CONTROL_REGISTERS[register]["write"])
            writes.append((register, value))
            register_state[register] = value
            events.append({
                "op": "write-control-register",
                "register": register,
                "value": expression_text(value),
            })
        elif opcode == "clear-low-bits" and set(instruction) == {"bits", "op"}:
            if value is None or returned:
                raise SpecError(f"{operation['name']}: native transform has no live value")
            mask = clear_low_mask(instruction["bits"], operation["name"])
            output.extend(bytes.fromhex("4825"))  # and imm32-sign-extended,%rax
            output.extend(struct.pack("<i", mask))
            value = ("clear-low-bits", instruction["bits"], value)
            events.append({
                "bits": instruction["bits"],
                "op": "clear-low-bits",
                "value": expression_text(value),
            })
        elif opcode == "return" and set(instruction) == {"op"}:
            if value is None or returned:
                raise SpecError(f"{operation['name']}: invalid native return")
            returned = True
            events.append({"op": "return", "value": expression_text(value)})
        else:
            raise SpecError(f"{operation['name']}: unsupported native opcode {opcode!r}")
    if not returned:
        raise SpecError(f"{operation['name']}: native program must return")
    registers = {
        event["register"] for event in events
        if "register" in event
    }
    if len(registers) != 1:
        raise SpecError(f"{operation['name']}: state trace must use one control register")
    register = registers.pop()
    metadata = CONTROL_REGISTERS[register]
    before = ("register-before", register)
    root_bits = metadata["normalize_bits"]
    normalized_before = ("clear-low-bits", root_bits, before)
    if (operation["precondition"]["right"]["bits"] != root_bits or
            operation["precondition"]["right"]["input"] !=
            f"hardware.{register}"):
        raise SpecError(f"{operation['name']}: precondition does not match control-register trace")
    if writes:
        if (len(writes) > metadata["max_writes"] or
                metadata["write_source"] != "register-before" or
                any(written_register != register or source != before
                    for written_register, source in writes)):
            raise SpecError(
                f"{operation['name']}: control-register write violates metadata")
        if metadata["readback_required"]:
            if register not in read_after_write:
                raise SpecError(
                    f"{operation['name']}: required control-register readback is absent")
            terminal_source = ("register-after", register, writes[-1][1])
        else:
            terminal_source = writes[-1][1]
        inferred_effects = metadata["write_effects"]
        expected_post = metadata["write_post_state"]
    else:
        terminal_source = before
        inferred_effects = metadata["read_effects"]
        expected_post = metadata["read_post_state"]
    if value != ("clear-low-bits", root_bits, terminal_source):
        raise SpecError(
            f"{operation['name']}: terminal value violates control-register metadata")
    if operation["effects"] != inferred_effects:
        raise SpecError(f"{operation['name']}: declared effects do not match native state trace")
    if operation["postcondition"]["left"] != expected_post:
        raise SpecError(f"{operation['name']}: postcondition does not match terminal native value")
    trace = {
        "architecture_observations": (
            metadata["write_observations"] if writes else []),
        "effects": inferred_effects,
        "events": events,
        "postcondition": operation["postcondition"],
        "precondition": operation["precondition"],
        "terminal_value": expression_text(value),
    }
    return bytes(output), trace


def native_bytes(operation: dict[str, Any]) -> bytes:
    return native_lower(operation)[0]


def architecture_requirements(trace: dict[str, Any]) -> int:
    requirements = 0
    if "cr3.write.noflush-bit-clear" in trace["architecture_observations"]:
        requirements |= 1
    return requirements


def control_binding(operation: dict[str, Any]) -> tuple[int, int, int, str]:
    registers = {
        item.get("register") for item in operation["native_ir"]
        if isinstance(item, dict) and item.get("op") in {
            "read-control-register", "write-control-register"
        }
    }
    writes = [
        item for item in operation["native_ir"]
        if isinstance(item, dict) and item.get("op") == "write-control-register"
    ]
    if len(registers) != 1:
        raise SpecError(f"{operation['name']}: control payload must bind one register")
    register = registers.pop()
    if register not in CONTROL_REGISTERS:
        raise SpecError(f"{operation['name']}: control payload register is unsupported")
    action = "reload" if writes else "observe"
    metadata = CONTROL_REGISTERS[register]
    return (metadata["payload_id"], CONTROL_ACTIONS[action],
            metadata["normalize_bits"], metadata["shadow_constant"])


def check_semantics(operation: dict[str, Any]) -> None:
    precondition = operation["precondition"]
    if (not isinstance(precondition, dict) or set(precondition) != {"left", "right"} or
            precondition["left"] != "staged-u64"):
        raise SpecError(f"{operation['name']}: malformed equivalence precondition")
    right = precondition["right"]
    if (not isinstance(right, dict) or
            set(right) != {"bits", "input", "op"} or
            right["op"] != "clear-low-bits" or
            not isinstance(right["input"], str) or
            not right["input"].startswith("hardware.")):
        raise SpecError(f"{operation['name']}: unsupported precondition expression")
    clear_low_mask(right["bits"], operation["name"])
    register = right["input"].removeprefix("hardware.")
    if register not in CONTROL_REGISTERS:
        raise SpecError(f"{operation['name']}: unknown precondition register")
    metadata = CONTROL_REGISTERS[register]
    postcondition = operation["postcondition"]
    if (not isinstance(postcondition, dict) or
            set(postcondition) != {"left", "right"} or
            postcondition["left"] not in {
                metadata["read_post_state"], metadata["write_post_state"]
            } or
            postcondition["right"] != "staged-u64"):
        raise SpecError(f"{operation['name']}: unsupported postcondition")
    if operation["shadow_source"] not in metadata["shadow_sources"]:
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
        native_bytes(operation)
        proof_template(operation)
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


def c_insns(program: bytes) -> list[str]:
    rendered = []
    for offset in range(0, len(program), 8):
        code, regs, insn_off, imm = struct.unpack("<BBhi", program[offset:offset + 8])
        rendered.append(
            "\t{ .code = 0x%02x, .dst_reg = %u, .src_reg = %u, "
            ".off = %d, .imm = %d }," %
            (code, regs & 0x0F, regs >> 4, insn_off, imm))
    return rendered


def render(operations: list[dict[str, Any]]) -> tuple[bytes, bytes, bytes, bytes]:
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
    commitment_proofs = []
    commitment_entries = []
    commitments = [
        "/* Generated by scripts/ebpfos-koperation-gen.py; do not edit. */",
        "#ifndef EBPFOS_KOPERATION_COMMITMENTS_H",
        "#define EBPFOS_KOPERATION_COMMITMENTS_H",
        "#include <linux/bpf.h>",
        "#include <stdint.h>",
        "struct ebpfos_koperation_commitment {",
        "\tuint32_t operation_id;",
        "\tuint32_t proof_effect_xor;",
        "\tuint32_t proof_insn_count;",
        "\tuint32_t proof_imm64_insn;",
        "\tconst struct bpf_insn *proof_template;",
        "\tunsigned char semantic_sha256[32];",
        "\tunsigned char proof_template_sha256[32];",
        "\tunsigned char native_sha256[32];",
        "\tunsigned char equivalence_sha256[32];",
        "};",
    ]
    for operation in operations:
        proof, immediate_index = proof_template(operation)
        native, trace = native_lower(operation)
        semantic_sha = digest(canonical(operation))
        proof_sha = digest(proof)
        native_sha = digest(native)
        equivalence = {
            "effect_commitment_u32": proof_effect_xor(operation),
            "effects_sha256": digest(canonical(operation["effects"])),
            "native_ir_sha256": digest(canonical(operation["native_ir"])),
            "native_trace_sha256": digest(canonical(trace)),
            "postcondition_sha256": digest(canonical(operation["postcondition"])),
            "precondition_sha256": digest(canonical(operation["precondition"])),
            "proof_ir_sha256": digest(canonical(operation["proof_ir"])),
            "result": operation["result"],
        }
        equivalence_sha = digest(canonical(equivalence))
        (control_register, control_action, normalize_bits,
         shadow_constant) = control_binding(operation)
        sym = symbol(operation["name"])
        proof_name = f"ebpfos_koperation_proof_{operation['id']}"
        header.extend([
            f"extern u64 {sym}(void);",
            f"extern const u32 {sym}_body_end_delta;",
            f"static const struct bpf_insn {proof_name}[] = {{",
            *c_insns(proof),
            "};",
            "",
        ])
        commitment_proofs.extend([
            f"static const struct bpf_insn ebpfos_koperation_commitment_proof_{operation['id']}[] = {{",
            *c_insns(proof),
            "};",
            "",
        ])
        assembly.extend([
            f"SYM_FUNC_START({sym})",
            "\t.byte " + ", ".join(f"0x{byte:02x}" for byte in native),
            f".L{sym}_body_end:",
            "\tRET",
            f"SYM_FUNC_END({sym})",
            ".pushsection .rodata, \"a\"",
            f".globl {sym}_body_end_delta",
            ".balign 4",
            f".type {sym}_body_end_delta, @object",
            f"{sym}_body_end_delta:",
            f"\t.long .L{sym}_body_end - {sym}",
            f".size {sym}_body_end_delta, 4",
            ".popsection",
            "",
        ])
        descriptors.append(
            "\t{\n"
            f"\t\t.operation_id = {operation['id']}U,\n"
            f"\t\t.architecture_requirements = {architecture_requirements(trace)}U,\n"
            f"\t\t.kprog_control_register = {control_register}U,\n"
            f"\t\t.kprog_control_action = {control_action}U,\n"
            f"\t\t.kprog_normalize_bits = {normalize_bits}U,\n"
            f"\t\t.proof_insns = {proof_name},\n"
            f"\t\t.proof_insn_count = ARRAY_SIZE({proof_name}),\n"
            f"\t\t.proof_imm64_insn = {immediate_index}U,\n"
            f"\t\t.shadow_source = {shadow_constant},\n"
            f"\t\t.native_emit = {sym},\n"
            f"\t\t.native_body_end_delta = &{sym}_body_end_delta,\n"
            f"\t\t.native_body_size = {len(native)}U,\n"
            f"\t\t.semantic_sha256 = {{ {c_bytes(semantic_sha)} }},\n"
            f"\t\t.proof_template_sha256 = {{ {c_bytes(proof_sha)} }},\n"
            f"\t\t.native_sha256 = {{ {c_bytes(native_sha)} }},\n"
            f"\t\t.equivalence_sha256 = {{ {c_bytes(equivalence_sha)} }},\n"
            "\t},")
        commitment_entries.extend([
            "\t{",
            f"\t\t.operation_id = {operation['id']}U,",
            f"\t\t.proof_effect_xor = 0x{proof_effect_xor(operation):08x}U,",
            f"\t\t.proof_insn_count = {len(proof) // 8}U,",
            f"\t\t.proof_imm64_insn = {immediate_index}U,",
            f"\t\t.proof_template = ebpfos_koperation_commitment_proof_{operation['id']},",
            f"\t\t.semantic_sha256 = {{ {c_bytes(semantic_sha)} }},",
            f"\t\t.proof_template_sha256 = {{ {c_bytes(proof_sha)} }},",
            f"\t\t.native_sha256 = {{ {c_bytes(native_sha)} }},",
            f"\t\t.equivalence_sha256 = {{ {c_bytes(equivalence_sha)} }},",
            "\t},",
        ])
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
            "native_trace": trace,
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
    commitments.extend(commitment_proofs)
    commitments.extend([
        "static const struct ebpfos_koperation_commitment",
        "ebpfos_koperation_commitments[] = {",
        *commitment_entries,
        "};",
        "#endif",
        "",
    ])
    return ("\n".join(header).encode(), "\n".join(assembly).encode(),
            canonical(certificate), "\n".join(commitments).encode())


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
    parser.add_argument("--userspace-header", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        outputs = render(load_spec(args.spec))
        for path, data in zip(
                (args.header, args.assembly, args.certificate,
                 args.userspace_header), outputs):
            write_or_check(path, data, args.check)
    except SpecError as error:
        print(f"ebpfos-koperation-gen: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
