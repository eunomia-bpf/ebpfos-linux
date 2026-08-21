# SPDX-License-Identifier: GPL-2.0-only
obj-y += admission.o admission_certificates.o state_adapter.o component_graph.o executor_root.o core.o object.o file.o ops.o dispatch.o
obj-$(CONFIG_EBPFOS_KOPERATION) += koperation.o koperation-generated.o

EBPFOS_KOPERATION_GENERATOR ?= $(srctree)/scripts/ebpfos-koperation-gen.py

quiet_cmd_ebpfos_koperation_gen = KOPGEN  $@
      cmd_ebpfos_koperation_gen = \
	$(PYTHON3) $(EBPFOS_KOPERATION_GENERATOR) \
		--spec $(src)/koperation-operations.json \
		--header $(obj)/koperation-generated.h \
		--assembly $(obj)/koperation-generated.S \
		--certificate $(obj)/koperation-certificate.json \
		--userspace-header $(obj)/koperation-commitments.h

$(obj)/koperation-generated.h $(obj)/koperation-generated.S \
	$(obj)/koperation-certificate.json $(obj)/koperation-commitments.h &: \
		$(src)/koperation-operations.json \
	$(EBPFOS_KOPERATION_GENERATOR) FORCE
	$(call if_changed,ebpfos_koperation_gen)

$(obj)/koperation.o: $(obj)/koperation-generated.h
$(obj)/koperation-generated.o: $(obj)/koperation-generated.S

targets += koperation-generated.h koperation-generated.S \
	   koperation-certificate.json koperation-commitments.h
always-y += koperation-certificate.json

$(obj)/admission_certificates.o: $(obj)/ebpfos_x509_certificate_list

hostprogs := ebpfos-extract-cert

quiet_cmd_ebpfos_copy_extract_cert = COPY    $@
      cmd_ebpfos_copy_extract_cert = cp $< $@

$(obj)/ebpfos-extract-cert.c: $(srctree)/certs/extract-cert.c FORCE
	$(call if_changed,ebpfos_copy_extract_cert)

HOSTCFLAGS_ebpfos-extract-cert.o = \
	$(shell $(HOSTPKG_CONFIG) --cflags libcrypto 2> /dev/null) \
	-I$(srctree)/scripts
HOSTLDLIBS_ebpfos-extract-cert = \
	$(shell $(HOSTPKG_CONFIG) --libs libcrypto 2> /dev/null || echo -lcrypto)

quiet_cmd_ebpfos_extract_certs = CERT    $@
      cmd_ebpfos_extract_certs = \
	$(if $(CONFIG_EBPFOS_TRUSTED_KEYS),\
	$(obj)/ebpfos-extract-cert "$(CONFIG_EBPFOS_TRUSTED_KEYS)" $@,\
	echo "CONFIG_EBPFOS_TRUSTED_KEYS must name exactly one certificate" >&2; false)

$(obj)/ebpfos_x509_certificate_list: $(CONFIG_EBPFOS_TRUSTED_KEYS) \
					$(obj)/ebpfos-extract-cert FORCE
	$(call if_changed,ebpfos_extract_certs)

targets += ebpfos-extract-cert.c ebpfos_x509_certificate_list
