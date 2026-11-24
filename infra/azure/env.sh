#!/usr/bin/env bash
# Shared settings for every script. Sourced, never executed.
# Values come from the repository's gitignored .env (template: .env.example).

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ ! -f "$REPO_ROOT/.env" ]]; then
	echo "missing $REPO_ROOT/.env: cp .env.example .env and fill it in" >&2
	return 1 2>/dev/null || exit 1
fi
set -a
# shellcheck disable=SC1091
source "$REPO_ROOT/.env"
set +a

: "${AZ_SUBSCRIPTION:?set AZ_SUBSCRIPTION in .env}"
: "${AZ_RESOURCE_GROUP:?set AZ_RESOURCE_GROUP in .env}"
: "${AZ_LOCATION:=westus3}"
: "${OPERATOR_VM:=shirudo-operator}"
: "${TARGET_VM:=shirudo-target}"
: "${ADMIN_USER:=azureuser}"
SSH_KEY="${SSH_KEY/#\~/$HOME}"

az_() { az "$@" --subscription "$AZ_SUBSCRIPTION" --only-show-errors; }

vm_ip() {
	az_ vm show -d -g "$AZ_RESOURCE_GROUP" -n "$1" --query publicIps -o tsv
}

vm_private_ip() {
	az_ vm show -d -g "$AZ_RESOURCE_GROUP" -n "$1" --query privateIps -o tsv
}

SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$REPO_ROOT/.state/known_hosts"
	-o ServerAliveInterval=30 -o ConnectTimeout=15 -o LogLevel=ERROR)

# Cache public IPs so demo scripts do not call Azure on every step.
host_of() {
	local vm="$1" cache="$REPO_ROOT/.state/ip-$1"
	mkdir -p "$REPO_ROOT/.state"
	if [[ ! -s "$cache" ]]; then
		vm_ip "$vm" >"$cache"
	fi
	cat "$cache"
}

on_operator() { ssh "${SSH_OPTS[@]}" "$ADMIN_USER@$(host_of "$OPERATOR_VM")" "$@"; }
on_target() { ssh "${SSH_OPTS[@]}" "$ADMIN_USER@$(host_of "$TARGET_VM")" "$@"; }
to_operator() { scp "${SSH_OPTS[@]}" -q "$@"; }
operator_dest() { echo "$ADMIN_USER@$(host_of "$OPERATOR_VM"):$1"; }
target_dest() { echo "$ADMIN_USER@$(host_of "$TARGET_VM"):$1"; }
