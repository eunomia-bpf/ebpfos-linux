Per-CPU area type view
=====================

``--percpu-layout SYMBOL`` describes the existing ``.data..percpu`` section
as one BTF struct and one BTF VAR referring to a zero-storage linker alias.
The alias must be at the ELF section start, with the same section extent.
Each struct member retains its original variable's name, type and offset;
incompatible sizes, overlaps and unsupported member offsets fail generation.
No storage, verifier limit or read-side pointer fact changes.

The DATASEC contains only the area VAR. Listing the alias alongside its
members would violate the stock non-overlap check. Original VAR records
remain, but consumers must use the area's member offsets for per-CPU
selection. Ordinary symbol-based consumers must therefore migrate together
with their write-authority metadata before enabling this option.

For the x86 L1 build, ``VMLINUX_PERCPU_LAYOUT=1`` enables the view. The
default stays off during consumer migration. Stock BPF CPU selection types
the area as a bounded BTF object and the x86 JIT selects it with one GS ADD.
Writes still require the active function's exact field authority and pass
the ordinary typed-store checks. Padding does not create writable fields.
