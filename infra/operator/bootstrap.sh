#!/usr/bin/env bash
# Runs ON the operator VM. Installs the toolchain shirudo and its kernel
# build need and checks out shirudo at the pinned commit.
#
#   bootstrap.sh
set -euo pipefail

[[ $# == 0 ]] || { echo 'usage: bootstrap.sh (revision comes from patches/shirudo/BASE)' >&2; exit 2; }
here="$(cd "$(dirname "$0")/../.." && pwd)"
SHIRUDO_COMMIT="$(cat "$here/patches/shirudo/BASE")"
[[ "$SHIRUDO_COMMIT" =~ ^[a-f0-9]{40}$ ]] || { echo 'invalid upstream pin' >&2; exit 1; }
SHIRUDO_DIR="$HOME/shirudo"
export DEBIAN_FRONTEND=noninteractive
APT=(sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get -o DPkg::Lock::Timeout=600 -y)

log() { printf '[bootstrap] %s\n' "$*" >&2; }

if command -v cloud-init >/dev/null; then
	sudo cloud-init status --wait >/dev/null || true
fi

log "apt packages"
"${APT[@]}" update -q
"${APT[@]}" install -q --no-install-recommends \
	build-essential git curl jq python3 python3-venv pkg-config gpg ca-certificates \
	libssl-dev openssl libelf-dev zlib1g-dev libzstd-dev libcurl4-openssl-dev \
	libtss2-dev libluajit-5.1-dev cryptsetup-bin e2fsprogs \
	flex bison bc dwarves cpio zstd xz-utils rsync kmod lsb-release \
	dpkg-dev fakeroot debhelper devscripts \
	dracut-core systemd-ukify systemd-boot-efi \
	tpm2-tools file openssh-client libcap2-bin \
	autoconf autoconf-archive automake libtool libltdl-dev gettext uuid-dev libjson-c-dev

log "clang and LLVM 23 (upstream installer)"
if [[ ! -d "$SHIRUDO_DIR/.git" ]]; then
	git init -q "$SHIRUDO_DIR"
	git -C "$SHIRUDO_DIR" remote add origin https://github.com/shirudo-dev/shirudo.git
fi
[[ "$(git -C "$SHIRUDO_DIR" remote get-url origin)" == https://github.com/shirudo-dev/shirudo.git ]]
[[ -z "$(git -C "$SHIRUDO_DIR" status --porcelain)" ]] || { log "refusing a modified source checkout"; exit 1; }
git -C "$SHIRUDO_DIR" fetch -q --no-tags --depth=1 origin "$SHIRUDO_COMMIT"
git -C "$SHIRUDO_DIR" checkout -q --detach "$SHIRUDO_COMMIT"
[[ "$(git -C "$SHIRUDO_DIR" rev-parse HEAD)" == "$SHIRUDO_COMMIT" ]]
if ! /usr/bin/clang --version 2>/dev/null | grep -q 'version 23'; then
	sudo sh "$SHIRUDO_DIR/.github/scripts/install-clang.sh"
fi
# The kernel build links with ld.lld-23 and the LLVM 23 binutils.
"${APT[@]}" install -q --no-install-recommends lld-23 llvm-23
# Static links of the distribution libcrypto (shirudo-quote-check).
sudo sh "$SHIRUDO_DIR/.github/scripts/install-static-libcrypto-deps.sh"

log "versions"
openssl version
/usr/bin/clang --version | head -1
openssl list -public-key-algorithms | grep -i ml-dsa >/dev/null || { log "OpenSSL lacks ML-DSA"; exit 1; }
log "done"
