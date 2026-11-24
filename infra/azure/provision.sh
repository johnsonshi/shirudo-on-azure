#!/usr/bin/env bash
# Create the two Azure VMs that run Shirudo:
#
#   operator  Ubuntu VM that builds the kernel and shirudo, holds the signing
#             keys and signs every shield. It never runs as a target.
#   target    Trusted Launch VM (Generation 2, vTPM on, Secure Boot off) that
#             boots the shirudo kernel and enforces the shields.
#
# Idempotent: existing resources are left as they are.
set -euo pipefail
source "$(dirname "$0")/env.sh"

: "${ALLOWED_SSH_CIDR:?set ALLOWED_SSH_CIDR in .env (your public IP/32)}"
# Space-separated CIDRs or NSG service tags. Behind a corporate secure web
# gateway (for example Global Secure Access), SSH leaves from rotating
# Azure-hosted egress IPs: add the AzureCloud tag; key-only auth stays on.
read -r -a SSH_SOURCES <<<"${ALLOWED_SSH_SOURCES:-$ALLOWED_SSH_CIDR}"
: "${OPERATOR_SIZE:=Standard_D32ds_v5}"
: "${TARGET_SIZE:=Standard_D4ds_v5}"
: "${UBUNTU_IMAGE:=Canonical:ubuntu-26_04-lts:server:latest}"

log() { printf '[provision] %s\n' "$*" >&2; }

if [[ ! -f "$SSH_KEY" ]]; then
	ssh-keygen -q -t ed25519 -f "$SSH_KEY" -N '' -C shirudo-on-azure
fi

log "resource group in $AZ_LOCATION"
az_ group create -n "$AZ_RESOURCE_GROUP" -l "$AZ_LOCATION" --tags purpose=shirudo-demo -o none

if ! az_ network vnet show -g "$AZ_RESOURCE_GROUP" -n shirudo-vnet -o none 2>/dev/null; then
	log "virtual network and NSG (SSH only from ${SSH_SOURCES[*]})"
	az_ network nsg create -g "$AZ_RESOURCE_GROUP" -n shirudo-nsg -o none
	az_ network nsg rule create -g "$AZ_RESOURCE_GROUP" --nsg-name shirudo-nsg -n allow-ssh \
		--priority 1000 --access Allow --protocol Tcp --direction Inbound \
		--source-address-prefixes "${SSH_SOURCES[@]}" --destination-port-ranges 22 -o none
	az_ network vnet create -g "$AZ_RESOURCE_GROUP" -n shirudo-vnet --address-prefixes 10.42.0.0/16 \
		--subnet-name vms --subnet-prefixes 10.42.1.0/24 --network-security-group shirudo-nsg -o none
fi

create_vm() {
	local name="$1" size="$2" disk="$3"; shift 3
	if az_ vm show -g "$AZ_RESOURCE_GROUP" -n "$name" -o none 2>/dev/null; then
		log "$name exists"
		return
	fi
	log "creating $name ($size)"
	az_ vm create -g "$AZ_RESOURCE_GROUP" -n "$name" --image "$UBUNTU_IMAGE" --size "$size" \
		--admin-username "$ADMIN_USER" --ssh-key-values "$SSH_KEY.pub" \
		--vnet-name shirudo-vnet --subnet vms --nsg "" --public-ip-sku Standard \
		--os-disk-size-gb "$disk" --storage-sku Premium_LRS \
		--accelerated-networking false "$@" -o none
	az_ vm boot-diagnostics enable -g "$AZ_RESOURCE_GROUP" -n "$name" -o none
}

# The operator compiles a kernel: many cores, a large disk.
create_vm "$OPERATOR_VM" "$OPERATOR_SIZE" 256 --security-type TrustedLaunch \
	--enable-secure-boot true --enable-vtpm true
# The target boots a kernel that Microsoft's UEFI CA did not sign, so Secure
# Boot is off; the vTPM stays on because shirudo anchors its register there.
create_vm "$TARGET_VM" "$TARGET_SIZE" 64 --security-type TrustedLaunch \
	--enable-secure-boot false --enable-vtpm true

rm -f "$REPO_ROOT/.state/ip-"*
log "operator: $(host_of "$OPERATOR_VM")"
log "target:   $(host_of "$TARGET_VM")"
