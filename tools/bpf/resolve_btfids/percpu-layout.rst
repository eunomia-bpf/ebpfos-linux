Per-CPU area type view
=====================

``--percpu-layout SYMBOL`` describes the existing ``.data..percpu`` section
as one BTF struct and one BTF VAR referring to a zero-storage linker alias.
Each struct member retains its original variable's name, type and offset;
the ordinary BTF constructors encode the resulting layout.
No storage, verifier limit or read-side pointer fact changes.

The DATASEC contains only the area VAR. Listing the alias alongside its
members would violate the stock non-overlap check. Original VAR records
remain, but consumers must use the area's member offsets for per-CPU
selection.

The x86 L1 build enables the view by default; ``VMLINUX_PERCPU_LAYOUT=0``
retains the original inventory for stock comparison controls. Stock CPU selection types
the area as a bounded BTF object and the x86 JIT selects it with one GS ADD.
The 2026-11-20 operator removal order deleted the additional alias, overlap,
extent and member preflights and the ``--field-obligations`` metadata injection.
An absent per-CPU DATASEC retains the source BTF. Ordinary BTF constructor and
upstream load errors are still reported.
