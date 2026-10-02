#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )) || [[ -z "${1//[[:space:]]/}" ]]; then
    printf 'Usage: %s "commit message"\n' "$0" >&2
    exit 2
fi

message=$1
if [[ "${message,,}" == *push* ]]; then
    printf 'Commit message cannot contain "push".\n' >&2
    exit 2
fi

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
git add --all
if git diff --cached --quiet; then
    printf 'No changes to commit.\n' >&2
    exit 1
fi
git commit -m "$message"
