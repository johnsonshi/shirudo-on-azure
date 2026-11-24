#!/usr/bin/env bash
# Runs ON the target VM as root, booted on the shirudo kernel. Turns on
# enforcement from the next boot, following shirudo's boot integration
# guide and its AWS image recipe:
#
#   1. install the target package (static shirudo, units, shirudo-gen-initrd,
#      the dracut module) and the UKI tooling
#   2. place the runtime and config images in /var/lib/shirudo/images
#   3. install the unit drop-ins that run the runtime image's binary
#   4. build the shirudo initrd and a unified kernel image (systemd-stub,
#      so PCR 11 measures the boot phases) with both keyring parameters
#   5. add a GRUB entry that chainloads the UKI and arm a one-shot boot
#
#   enable-shirudo.sh [--reset-state] <bundle-dir>
#
# --reset-state wipes /var/lib/shirudo so that the next boot is a first
# boot again (init labels the state tree only then). It refuses to run
# while enforcement is up: boot the plain kernel entry first.
set -euo pipefail

reset=0
if [[ "${1:-}" == --reset-state ]]; then reset=1; shift; fi
bundle="${1:?usage: enable-shirudo.sh [--reset-state] <bundle-dir>}"
here="$(cd "$(dirname "$0")" && pwd)"
krel="$(cat /etc/shirudo-kernel-release)"
log() { printf '[enable-shirudo] %s\n' "$*" >&2; }
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l

[[ "$(uname -r)" == "$krel" ]] || { log "boot $krel first (running $(uname -r))"; exit 1; }
grep -qw bpf.keyring_unsealed=1 /proc/cmdline || { log "cmdline lacks bpf.keyring_unsealed=1"; exit 1; }
grep -qw dm_verity.keyring_unsealed=1 /proc/cmdline || { log "cmdline lacks dm_verity.keyring_unsealed=1"; exit 1; }
(cd "$bundle" && sha256sum -c --quiet SHA256SUMS)
if mountpoint -q /run/shirudo/runtime; then
	log "enforcement is up; files under /var/lib/shirudo are sealed. Boot the plain kernel entry first."
	exit 1
fi

log "packages"
apt-get install -y -q dracut systemd-ukify systemd-boot-efi libtss2-tcti-device0 tpm2-tools >/dev/null
apt-get install -y -q --reinstall "$bundle"/shirudo-target_*.deb >/dev/null
command -v shirudo-gen-initrd >/dev/null

if [[ $reset == 1 ]]; then
	log "resetting /var/lib/shirudo for a first boot"
	rm -rf /var/lib/shirudo
fi

log "images and the operator certificate"
install -d -m 0700 -o root -g root /var/lib/shirudo /var/lib/shirudo/images /var/lib/shirudo/keys
# Read by the cert_on_disk pre-flight of the root file system run.
install -m 0644 -o root -g root "$bundle/bpf-cert.der" /var/lib/shirudo/keys/cert.der
for f in runtime.img runtime.verity runtime.roothash initial.img initial.verity initial.roothash initial.p7s; do
	install -m 0644 -o root -g root "$bundle/$f" /var/lib/shirudo/images/
done

log "unit drop-ins"
install -D -m 0644 "$bundle/runtime-service.conf" /etc/systemd/system/shirudo.service.d/runtime.conf
dropin() { # unit, ExecStart lines...
	local unit="$1"; shift
	install -d "/etc/systemd/system/$unit.service.d"
	{ echo "[Service]"; echo "ExecStart="; printf 'ExecStart=%s\n' "$@"; } \
		>"/etc/systemd/system/$unit.service.d/runtime.conf"
}
rt=/run/shirudo/runtime/usr/bin/shirudo
dropin shirudo-keepalive "$rt status --otel"
dropin shirudo-map-export "$rt upatch map --all"
dropin shirudo-bpm-repo-update "-$rt bpm repo update" "$rt bpm upgrade"
dropin shirudo-bpm-tree-sync "$rt bpm tree sync"
dropin shirudo-xdp-reconcile "$rt upatch reconcile"
systemctl daemon-reload

# Housekeeping for a custom kernel on Azure: Ubuntu's KVP daemon wrapper
# looks for linux-cloud-tools of the running kernel, and the kernel has
# no dm-multipath.
systemctl mask -q hv-kvp-daemon.service multipathd.service multipathd.socket 2>/dev/null || true

log "dracut module: systemd's early TPM setup in the initrd"
rm -rf /usr/lib/dracut/modules.d/91shirudo-tpm2-setup
cp -a "$here/dracut/91shirudo-tpm2-setup" /usr/lib/dracut/modules.d/

log "initrd"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
install -m 0600 "$bundle/uki-bootstrap.conf" "$work/uki-bootstrap.conf"
# No early exit in awk: under pipefail a SIGPIPE in ldconfig would end the script.
tcti="$(ldconfig -p | awk '$1 == "libtss2-tcti-device.so.0" && !found { print $NF; found = 1 }')"
[[ -r "$tcti" ]] || { log "libtss2-tcti-device.so.0 is missing"; exit 1; }
initrd="/boot/initrd-shirudo-$krel.img"
# Name the packaged binary: a shirudo earlier on PATH could be a link into
# /run/shirudo/runtime, which dangles whenever enforcement is down.
rm -f /usr/local/bin/shirudo
shirudo-gen-initrd --bootstrap-conf "$work/uki-bootstrap.conf" --cert "$bundle/bpf-cert.der" \
	--binary /usr/bin/shirudo --binary-path /usr/bin/shirudo \
	--kver "$krel" --output "$initrd" -- --no-hostonly --install "$tcti" --add shirudo-tpm2-setup \
	--omit "lvm mdraid multipath bcache btrfs crypt systemd-cryptsetup fido2 pkcs11 nvdimm cifs virtfs virtiofs plymouth network network-manager systemd-networkd dyn-netconf qemu qemu-net overlayroot resume"
shirudo-gen-initrd --check "$initrd"
lsinitrd "$initrd" >"$work/initrd.list" 2>/dev/null
grep -q systemd-tpm2-setup-early.service "$work/initrd.list" ||
	{ log "systemd-tpm2-setup-early.service is missing from $initrd"; exit 1; }

log "unified kernel image"
cmdline="$(sed -E 's/(^|[[:space:]])BOOT_IMAGE=[^[:space:]]+//g; s/^[[:space:]]+//' /proc/cmdline)"
esp=/boot/efi
install -d "$esp/EFI/Linux"
uki="$esp/EFI/Linux/shirudo-$krel.efi"
ukify build --linux="/boot/vmlinuz-$krel" --initrd="$initrd" --cmdline="$cmdline" --output="$uki"
ukify inspect "$uki" >/dev/null
ls -la "$uki"

log "GRUB entry"
esp_uuid="$(grub-probe --target=fs_uuid "$esp")"
cat >/etc/grub.d/41_shirudo_uki <<EOF
#!/bin/sh
cat <<'GRUB_EOF'
menuentry 'Shirudo UKI ($krel)' --id shirudo-uki {
    insmod part_gpt
    insmod fat
    insmod chain
    search --no-floppy --fs-uuid --set=root $esp_uuid
    chainloader /EFI/Linux/shirudo-$krel.efi
}
GRUB_EOF
EOF
chmod 0755 /etc/grub.d/41_shirudo_uki
update-grub 2>/dev/null
grub-reboot shirudo-uki
# Interactive root shells: only the runtime image's binary has authority.
echo 'alias shirudo=/run/shirudo/runtime/usr/bin/shirudo' >/etc/profile.d/shirudo.sh
log "next boot only: Shirudo UKI ($krel); the saved default is unchanged"
grub-editenv list
