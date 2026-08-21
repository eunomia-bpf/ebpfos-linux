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
    variant = copy.deepcopy(root["operations"][0])
    variant["id"] = 2
    variant["name"] = "page-table.read-cr3-root-normalized"
    variant["effects"] = ["page_table.root.normalize", "page_table.root.observe"]
    variant["native_ir"].insert(-1, {"bits": 12, "op": "clear-low-bits"})
    variant["proof_ir"].insert(-1, {"bits": 12, "op": "clear-low-bits"})
    root["operations"].append(variant)

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
        if len(certificate["operations"]) != 2:
            raise SystemExit("second declarative operation was not generated")
        if assembly.count("0x48, 0x25, 0x00, 0xf0, 0xff, 0xff") != 3:
            raise SystemExit("native clear-low-bits opcodes were not composed")
        if header.count(".code = 0x57") != 1:
            raise SystemExit("proof clear-low-bits opcode was not composed")
        if assembly.count("\tRET") != 2 or "ANNOTATE_UNRET_SAFE" in assembly:
            raise SystemExit("generated operations did not use the kernel return ABI")
        if any(item["generator_proof_status"] != "bound-unproved"
               for item in certificate["operations"]):
            raise SystemExit("generator overclaimed equivalence proof")
        if any(item["return_abi"] != "kernel-rethunk"
               for item in certificate["operations"]):
            raise SystemExit("generated operation omitted the kernel return ABI")

        (out / "generated.S").write_text(assembly + "/* forged */\n")
        forged = invoke(args.generator, spec, out, check=True)
        if forged.returncode == 0:
            raise SystemExit("forged generated native text was accepted")

        invalid = copy.deepcopy(root)
        invalid["operations"][1]["native_ir"][0]["register"] = "cr4"
        spec.write_text(json.dumps(invalid, sort_keys=True) + "\n")
        rejected = invoke(args.generator, spec, out)
        if rejected.returncode == 0:
            raise SystemExit("unknown control-register lowering was accepted")

    print("EBPFOS_KOPERATION_GENERATOR_PASS operations=2 forged_native=REJECT unknown_opcode=REJECT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
