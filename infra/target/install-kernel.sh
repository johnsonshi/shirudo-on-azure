#!/usr/bin/env bash
# Runs ON the target VM as root. Installs the shirudo kernel packages and
# arms a one-shot boot into them: the stock Azure kernel stays the saved
# GRUB default, so if the new kernel does not come up, `az vm restart`
# boots the old one again.
#
#   install-kernel.sh <dir-with-linux-image-deb>
set -euo pipefail

dir="${1:?usage: install-kernel.sh <kernel-package-dir>}"
log() { printf '[install-kernel] %s\n' "$*" >&2; }
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
[[ $EUID == 0 && $# == 1 && "$dir" == /* ]] || { log 'run as root with the verified bundle path'; exit 2; }

image_deb="$dir/kernel.deb"
krel="$(dpkg-deb -f "$image_deb" Package)"
[[ "$krel" == linux-image-*shirudo-azure* && "$krel" != *-dbg ]] || { log "not an Azure lab kernel"; exit 1; }
krel="${krel#linux-image-}"
log "kernel $krel"

# Both keyrings must stay open until shirudo init enrolls its certificates.
# A menu on the serial console lets you pick the stock kernel by hand.
cat >/etc/default/grub.d/99-shirudo.cfg <<'EOF'
GRUB_DEFAULT=saved
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=5
GRUB_TERMINAL="serial console"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1"
EOF

apt-get update -q >/dev/null
apt-get install -y -q "$image_deb" >/dev/null

# The root disk is already full size. Booted without an initrd, the kernel
# names the root /dev/root, and cloud-init's resize2fs /dev/sda1 then fails
# with EBUSY on every boot.
printf 'resize_rootfs: false\n' >/etc/cloud/cloud.cfg.d/99-shirudo-on-azure.cfg
update-grub 2>/dev/null

entry_id() { # $1 = kernel release
	local sub id
	sub="$(sed -nE "s/^submenu .*\\\$menuentry_id_option '([^']+)'.*/\1/p" /boot/grub/grub.cfg | head -1)"
	id="$(grep -E "^[[:space:]]*menuentry '.*, with Linux $1'" /boot/grub/grub.cfg |
		sed -nE "s/.*\\\$menuentry_id_option '([^']+)'.*/\1/p" | head -1)"
	[[ -n "$sub" && -n "$id" ]] && echo "$sub>$id"
}

stock="$(uname -r)"
case "$stock" in *shirudo*) stock="$(ls /boot/vmlinuz-*-azure | sed 's#.*/vmlinuz-##' | sort -V | tail -1)" ;; esac
stock_id="$(entry_id "$stock")"
new_id="$(entry_id "$krel")"
[[ -n "$stock_id" && -n "$new_id" ]] || { log "cannot find GRUB entries for $stock / $krel"; exit 1; }

grub-set-default "$stock_id"
grub-reboot "$new_id"
echo "$krel" >/etc/shirudo-kernel-release
log "saved default: $stock (stock); next boot only: $krel"
grub-editenv list
