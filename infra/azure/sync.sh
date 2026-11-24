#!/usr/bin/env bash
# Copy this repository's scripts (not .env, .state or drafts) to a VM.
#   sync.sh operator|target
set -euo pipefail
source "$(dirname "$0")/env.sh"
case "${1:?operator|target}" in
operator) host="$(host_of "$OPERATOR_VM")" ;;
target) host="$(host_of "$TARGET_VM")" ;;
*) echo "operator|target" >&2; exit 1 ;;
esac
rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
	--exclude .git --exclude .env --exclude '.env.*' --exclude .state --exclude .scratch \
	--exclude build --exclude artifacts \
	"$REPO_ROOT/" "$ADMIN_USER@$host:shirudo-on-azure/"
