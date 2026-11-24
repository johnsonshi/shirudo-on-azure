#!/usr/bin/env bash
# Runs ON the operator VM. Creates the operator keys once and builds the
# signed images a target boots with, following shirudo's boot integration
# guide: the config image (signed), the dm-verity runtime image holding the
# static target binary and the public certificates, and the UKI bootstrap
# that pins the runtime image's root hash.
#
#   make-target-bundle.sh            -> ~/build/target-bundle/
#
# Private keys stay in ~/shirudo-keys on this VM. The bundle holds only
# public certificates, images and the target package.
set -euo pipefail

[[ $# == 0 ]] || exit 2
umask 077
KEYS="$HOME/shirudo-keys"
PKGS="$HOME/build/shirudo"
OUT="$HOME/build/target-bundle"
CONFIG_PCR=13
here="$(cd "$(dirname "$0")/../.." && pwd)"
GEN=/usr/libexec/shirudo/gen-image
BUILDER=/usr/libexec/shirudo/shirudo-build

log() { printf '[bundle] %s\n' "$*" >&2; }

# One BPF signing key (signs every upatch) and one config signing key.
for dir in "$KEYS/bpf" "$KEYS/config"; do
	if [[ ! -s "$dir/signing_key.pem" ]]; then
		log "generating key in $dir"
		install -d -m 0700 "$dir"
		shirudo genkey --keys-dir "$dir"
	fi
done
chmod 0700 "$KEYS"

target_deb="$PKGS/target.deb"
shopt -s nullglob
kernel=("$HOME"/build/azure-kernel/latest/linux-image-*_amd64.deb)
[[ ${#kernel[@]} == 1 && "$(dpkg-deb -f "${kernel[0]}" Package)" == linux-image-*shirudo-azure* ]] ||
	{ log "expected one non-debug Azure kernel image package"; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
dpkg-deb -x "$target_deb" "$work/pkg"
target_bin="$work/pkg/usr/bin/shirudo"
file "$target_bin" | grep -q 'static' || { log "target binary is not static"; exit 1; }

mkdir -m 0700 "$OUT"

log "config image"
install -d "$work/config-root/etc/shirudo"
cat >"$work/config-root/etc/shirudo/shirudo.conf" <<'EOF'
# Initial config image for shirudo-on-azure targets.
eventlog.max_bytes = 0
EOF
"$GEN/shirudo-gen-image" --source "$work/config-root" --output "$OUT/initial" \
	--kind config --keys-dir "$KEYS/config" --builder "$BUILDER" >/dev/null
shirudo image verify "$OUT/initial" --cert "$KEYS/config/cert.der" >/dev/null

log "runtime image (config PCR $CONFIG_PCR)"
cat >"$work/runtime.conf" <<EOF
# Runtime bootstrap for shirudo-on-azure targets (Azure vTPM).
config.image = /var/lib/shirudo/images/initial
config.verification_key = /run/shirudo/runtime/etc/shirudo/config-cert.der
config.pcr = $CONFIG_PCR
tpm.tcti = device:/dev/tpmrm0
EOF
"$GEN/shirudo-gen-runtime" --binary "$target_bin" --bootstrap-conf "$work/runtime.conf" \
	--cert "$KEYS/bpf/cert.der" --config-cert "$KEYS/config/cert.der" \
	--output "$OUT/runtime" --keys-dir "$KEYS/config" --builder "$BUILDER" \
	--unit-output "$OUT/runtime-service.conf" >/dev/null

log "UKI bootstrap"
printf 'runtime.image = /var/lib/shirudo/images/runtime\nruntime.root_hash = %s\n' \
	"$(cat "$OUT/runtime.roothash")" >"$OUT/uki-bootstrap.conf"

cp "$KEYS/bpf/cert.der" "$OUT/bpf-cert.der"
cp "$target_deb" "$OUT/target.deb"
cp "${kernel[0]}" "$OUT/kernel.deb"
python3 "$here/infra/bundle.py" seal
log "bundle in $OUT"
ls -l "$OUT"
