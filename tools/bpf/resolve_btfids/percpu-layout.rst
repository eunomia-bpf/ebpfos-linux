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

The x86 L1 build enables the view by default; ``VMLINUX_PERCPU_LAYOUT=0``
retains the original inventory for stock comparison controls. Stock CPU selection types
the area as a bounded BTF object and the x86 JIT selects it with one GS ADD.
Writes still require the active function's exact field authority and pass
the ordinary typed-store checks. Padding does not create writable fields.

``--field-obligations FILE`` accepts justified type/field ``nonnull`` store
obligations from a separate TSV. It qualifies only that field's pointer type;
layout, original VAR records and nullable read typing stay unchanged. Every
typed store, including KOperation proofs, must preserve the obligation. The
current one is ``__percpu_layout.current_task``, whose stock helper promises a
non-null task. Qualified pointees are refused so an added tag cannot hide
address-space or RCU qualifications. Source consumers also check static
initialization against the same pointee layout before binding the symbol.

Area descriptors use offsets wide enough for the existing section and check
the original root extent and member authority. Only the inventory's descriptor
ABI is registered, so the registration count does not double during migration.
