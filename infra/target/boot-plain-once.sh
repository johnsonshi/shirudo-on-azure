#!/usr/bin/env bash
# Runs ON the target as root. Arms one boot of the shirudo kernel WITHOUT the
# UKI (no shirudo init, no seal), for maintenance such as resetting
# /var/lib/shirudo. The saved default (the Shirudo UKI) is unchanged.
set -euo pipefail
krel="$(cat /etc/shirudo-kernel-release)"
sub="$(sed -nE "s/^submenu .*\\\$menuentry_id_option '([^']+)'.*/\1/p" /boot/grub/grub.cfg | head -1)"
id="$(grep -E "^[[:space:]]*menuentry '.*, with Linux $krel'" /boot/grub/grub.cfg |
	sed -nE "s/.*\\\$menuentry_id_option '([^']+)'.*/\1/p" | head -1)"
[[ -n "$sub" && -n "$id" ]] || { echo "no GRUB entry for $krel" >&2; exit 1; }
grub-reboot "$sub>$id"
grub-editenv list
