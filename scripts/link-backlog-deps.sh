#!/usr/bin/env bash
# Second pass: rewrite each issue's "Depends on: SLUG, SLUG" line into
# real "#N" GitHub issue links using the slug->number mapping produced
# by create-backlog-issues.sh.
#
# Usage: scripts/link-backlog-deps.sh <owner/repo>
set -euo pipefail

REPO="${1:?usage: link-backlog-deps.sh <owner/repo>}"
BACKLOG="$(dirname "$0")/../.github/issues_backlog.json"
MAP_FILE="$(dirname "$0")/../.github/issues_map.json"

count=$(jq 'length' "$BACKLOG")
for i in $(seq 0 $((count - 1))); do
  entry=$(jq -c ".[$i]" "$BACKLOG")
  slug=$(echo "$entry" | jq -r '.slug')
  number=$(jq -r --arg s "$slug" '.[$s]' "$MAP_FILE")
  depend_slugs=$(echo "$entry" | jq -r '.depends_on[]' 2>/dev/null || true)

  if [ -z "$depend_slugs" ]; then
    continue
  fi

  links=""
  for dslug in $depend_slugs; do
    dnum=$(jq -r --arg s "$dslug" '.[$s]' "$MAP_FILE")
    if [ "$dnum" != "null" ]; then
      links="${links}#${dnum} (${dslug}), "
    fi
  done
  links="${links%, }"

  echo "Issue #$number ($slug) depends on: $links"
  gh issue view "$number" -R "$REPO" --json body -q .body \
    | sed "s/\*\*Depends on:\*\*.*/**Depends on:** ${links}/" \
    > /tmp/issue-body-$$.md
  gh issue edit "$number" -R "$REPO" --body-file "/tmp/issue-body-$$.md"
  rm -f "/tmp/issue-body-$$.md"
done

echo "Dependency linking pass complete."
