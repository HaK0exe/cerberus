#!/usr/bin/env bash
# One-shot script that bulk-creates the Sprint 2-6 backlog issues from
# .github/issues_backlog.json into the GitHub repo, then writes a
# slug -> issue-number mapping to .github/issues_map.json so a second
# pass can rewrite "Depends on" slugs into real #issue links.
#
# Usage: scripts/create-backlog-issues.sh <owner/repo>
set -euo pipefail

REPO="${1:?usage: create-backlog-issues.sh <owner/repo>}"
BACKLOG="$(dirname "$0")/../.github/issues_backlog.json"
MAP_FILE="$(dirname "$0")/../.github/issues_map.json"

echo "{}" > "$MAP_FILE"

count=$(jq 'length' "$BACKLOG")
for i in $(seq 0 $((count - 1))); do
  entry=$(jq -c ".[$i]" "$BACKLOG")
  slug=$(echo "$entry" | jq -r '.slug')
  title=$(echo "$entry" | jq -r '.title')
  milestone=$(echo "$entry" | jq -r '.milestone')
  priority=$(echo "$entry" | jq -r '.priority')
  estimate=$(echo "$entry" | jq -r '.estimate')
  summary=$(echo "$entry" | jq -r '.summary')
  depends=$(echo "$entry" | jq -r '.depends_on | join(", ")')
  acceptance=$(echo "$entry" | jq -r '.acceptance | map("- [ ] " + .) | join("\n")')
  labels=$(echo "$entry" | jq -r '(.labels + ["priority:" + (.priority)]) | join(",")')

  body=$(cat <<EOF
$summary

**Priority:** $priority
**Estimate:** $estimate
**Depends on:** ${depends:-none}
**Tracking ID:** $slug

**Acceptance criteria**
$acceptance
EOF
)

  echo "Creating [$slug] $title ..."
  url=$(gh issue create -R "$REPO" \
    --title "$title" \
    --body "$body" \
    --label "$labels" \
    --milestone "$milestone")

  number=$(basename "$url")
  jq --arg slug "$slug" --arg num "$number" '.[$slug] = $num' "$MAP_FILE" > "$MAP_FILE.tmp" && mv "$MAP_FILE.tmp" "$MAP_FILE"
done

echo "Done. Mapping written to $MAP_FILE"
