# SPDX-License-Identifier: GPL-2.0-only
obj-y += admission.o admission_certificates.o state_adapter.o core.o object.o file.o ops.o dispatch.o

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
