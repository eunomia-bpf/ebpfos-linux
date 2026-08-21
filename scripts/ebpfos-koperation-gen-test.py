#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Focused host test for declarative KOperation opcode composition."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import tempfile
from pathlib import Path


def invoke(generator: Path, spec: Path, out: Path, check: bool = False) -> subprocess.CompletedProcess[str]:
    command = [
        "python3", str(generator),
        "--spec", str(spec),
        "--header", str(out / "generated.h"),
        "--assembly", str(out / "generated.S"),
        "--certificate", str(out / "certificate.json"),
        "--userspace-header", str(out / "commitments.h"),
    ]
    if check:
        command.append("--check")
    return subprocess.run(command, check=False, text=True, capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generator", required=True, type=Path)
    parser.add_argument("--spec", required=True, type=Path)
    args = parser.parse_args()

    root = json.loads(args.spec.read_text())
    with tempfile.TemporaryDirectory(prefix="ebpfos-koperation-") as temporary:
        out = Path(temporary)
        spec = out / "operations.json"
        spec.write_text(json.dumps(root, sort_keys=True) + "\n")
        generated = invoke(args.generator, spec, out)
        if generated.returncode:
            raise SystemExit(generated.stderr)
        checked = invoke(args.generator, spec, out, check=True)
        if checked.returncode:
            raise SystemExit(checked.stderr)

        assembly = (out / "generated.S").read_text()
        certificate = json.loads((out / "certificate.json").read_text())
        header = (out / "generated.h").read_text()
        commitments = (out / "commitments.h").read_text()
        if len(certificate["operations"]) != 2:
            raise SystemExit("declarative operations were not generated")
        if assembly.count("0x48, 0x25, 0x00, 0xf0, 0xff, 0xff") != 2:
            raise SystemExit("native clear-low-bits opcodes were not composed")
        if assembly.count("0x0f, 0x22, 0xd8") != 1:
            raise SystemExit("control-register write opcode was not composed")
        if header.count(".code = 0xa7") != 3:
            raise SystemExit("proof effect commitments were not composed")
        if "proof_template[" in commitments:
            raise SystemExit("userspace proof manifest has a fixed instruction ceiling")
        if assembly.count("\tRET") != 2 or "ANNOTATE_UNRET_SAFE" in assembly:
            raise SystemExit("generated operations did not use the kernel return ABI")
        if (header.count(".architecture_requirements = 0U") != 1 or
                header.count(".architecture_requirements = 1U") != 1):
            raise SystemExit("generated architecture preconditions are not access-derived")
        if any(item["generator_proof_status"] != "bound-unproved"
               for item in certificate["operations"]):
            raise SystemExit("generator overclaimed equivalence proof")
        if any(item["return_abi"] != "kernel-rethunk"
               for item in certificate["operations"]):
            raise SystemExit("generated operation omitted the kernel return ABI")
        reload = certificate["operations"][1]
        if (reload["effects"] != [
                "page_table.root.preserve",
                "tlb.current-hardware-cr3-context.non-global.invalidate"] or
                reload["native_trace"]["architecture_observations"] != [
                    "cpu.before-after-equal",
                    "cr3.write.noflush-bit-clear",
                    "cr4.pcide-runtime-value",
                    "cr4.pge-runtime-value",
                    "executor.preemption-disabled",
                    "linux.flush-tlb-local.not-claimed",
                    "pti.user-companion-asid.not-modeled"]):
            raise SystemExit("CR3 architectural effect contract was overclaimed")

        (out / "generated.S").write_text(assembly + "/* forged */\n")
        forged = invoke(args.generator, spec, out, check=True)
        if forged.returncode == 0:
            raise SystemExit("forged generated native text was accepted")

        mutants = {
            "missing-readback": lambda item: item["native_ir"].pop(2),
            "wrong-source": lambda item: item["native_ir"][1].update(source="shadow"),
            "wrong-register": lambda item: item["native_ir"][1].update(register="cr4"),
            "tlb-without-write": lambda item: item["native_ir"].pop(1),
            "missing-effect": lambda item: item["effects"].pop(),
            "extra-effect": lambda item: item["effects"].append("tlb.remote.invalidate"),
            "terminal-mismatch": lambda item: item["native_ir"][3].update(bits=13),
        }
        for name, mutate in mutants.items():
            invalid = copy.deepcopy(root)
            mutate(invalid["operations"][1])
            if name == "tlb-without-write":
                invalid["operations"][1]["native_ir"].insert(
                    1, {"op": "read-control-register", "register": "cr3"})
            invalid["operations"][1]["effects"] = sorted(
                invalid["operations"][1]["effects"])
            spec.write_text(json.dumps(invalid, sort_keys=True) + "\n")
            rejected = invoke(args.generator, spec, out)
            if rejected.returncode == 0:
                raise SystemExit(f"{name} native/effect mutant was accepted")

    print("EBPFOS_KOPERATION_GENERATOR_PASS operations=2 declarative_write=PASS effect_commitment=PASS trace_mutants=REJECT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
