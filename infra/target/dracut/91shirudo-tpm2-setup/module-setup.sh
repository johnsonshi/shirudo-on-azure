#!/bin/bash
# Run systemd's early TPM setup (SRK and NvPCR definitions) in the initrd.
#
# On a measured UKI boot systemd defines its NvPCRs from /usr/lib/nvpcr
# with systemd-tpm2-setup-early.service. shirudo orders its initrd unit
# after that service and, once its guards attach, refuses NvPCR
# definitions from any other task. dracut 110 (Ubuntu 26.04) ships no
# module for the service, so it would run only after the switch to the
# root file system and be refused. This module puts it where shirudo
# expects it.

check() {
	[[ -x "$systemdutildir/systemd-tpm2-setup" ]] || return 1
	[[ -f "$systemdsystemunitdir/systemd-tpm2-setup-early.service" ]] || return 1
	return 255
}

depends() {
	echo systemd tpm2-tss systemd-pcrextend
	return 0
}

install() {
	inst_multiple -o \
		"$systemdutildir/systemd-tpm2-setup" \
		"$systemdsystemunitdir/systemd-tpm2-setup-early.service" \
		/usr/lib/nvpcr/*.nvpcr
	$SYSTEMCTL -q --root "$initdir" add-wants sysinit.target systemd-tpm2-setup-early.service
}
