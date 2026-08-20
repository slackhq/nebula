#!/usr/bin/env bash
#
# Backport a merged PR to a release branch.
#
# Cherry-picks the merge commit of a merged PR onto release-1.11 and opens a
# backport PR, mirroring the shape of #1842.
#
# Usage: ./backport.sh <pr-number> [target-version] [--continue]
#   pr-number       The merged PR to backport
#   target-version  Release version to target (default: 1.11)
#   --continue      Resume after resolving cherry-pick conflicts: assumes the
#                   fixes are staged, runs `git cherry-pick --continue`, and
#                   proceeds to push and open the backport PR.
#
# Requires: gh (authenticated), git, jq.

set -euo pipefail

PR_NUMBER=${1:?usage: backport.sh <pr-number> [target-version] [--continue]}
shift
CONTINUE=0
TARGET_VERSION=""
for arg in "$@"; do
  case "$arg" in
    --continue) CONTINUE=1 ;;
    *) TARGET_VERSION=$arg ;;
  esac
done

for cmd in gh git jq; do
  command -v "$cmd" >/dev/null || { echo "error: $cmd is required" >&2; exit 1; }
done

# Pull the source PR's metadata. Refuse to backport a PR that never merged.
pr_json=$(gh pr view "$PR_NUMBER" --json title,body,mergedAt,mergeCommit,milestone)
PR_TITLE=$(jq -r '.title' <<<"$pr_json")
PR_BODY=$(jq -r '.body' <<<"$pr_json")
MERGE_SHA=$(jq -r '.mergeCommit.oid // empty' <<<"$pr_json")
PR_MILESTONE=$(jq -r '.milestone.title // empty' <<<"$pr_json")

if [ "$(jq -r '.mergedAt // empty' <<<"$pr_json")" = "" ] || [ -z "$MERGE_SHA" ]; then
  echo "error: PR #${PR_NUMBER} is not merged (no merge commit to cherry-pick)" >&2
  exit 1
fi

# Default the target to one minor below the PR's milestone: a PR landing in
# v1.12.0 backports to release-1.11. An explicit target-version arg overrides.
if [ -z "$TARGET_VERSION" ]; then
  if [[ $PR_MILESTONE =~ ^v?([0-9]+)\.([0-9]+) ]]; then
    TARGET_VERSION="${BASH_REMATCH[1]}.$(( BASH_REMATCH[2] - 1 ))"
  else
    echo "error: PR #${PR_NUMBER} has no v<major>.<minor>.* milestone to infer the target from." >&2
    echo "Pass the target version explicitly, e.g. $0 ${PR_NUMBER} 1.11" >&2
    exit 1
  fi
fi
TARGET_BRANCH="release-${TARGET_VERSION}"

# Slug from the PR title: lower-case, non-alphanumerics to dashes, trimmed.
slug=$(printf '%s' "$PR_TITLE" \
  | tr '[:upper:]' '[:lower:]' \
  | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' \
  | cut -c1-50 \
  | sed -E 's/-+$//')
BRANCH="backport-${TARGET_VERSION//./-}-${slug}"

if [ "$CONTINUE" -eq 1 ]; then
  # Resuming: the branch already exists and a cherry-pick is mid-conflict.
  current=$(git rev-parse --abbrev-ref HEAD)
  if [ "$current" != "$BRANCH" ]; then
    echo "error: --continue expects to be on ${BRANCH}, but HEAD is ${current}" >&2
    exit 1
  fi
  echo "Resuming backport of #${PR_NUMBER} on ${BRANCH}"
  # Conflicts assumed resolved and staged; core.editor=true keeps the commit message.
  git -c core.editor=true cherry-pick --continue
else
  # A fresh run switches branches and cherry-picks, so tracked changes must be
  # clean. Untracked files are fine, and --continue is exempt (its resolved
  # conflicts are meant to be staged).
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "error: working tree has uncommitted changes to tracked files; commit or stash them first." >&2
    exit 1
  fi

  echo "Backporting #${PR_NUMBER} (${MERGE_SHA}) onto ${TARGET_BRANCH} as ${BRANCH}"

  git fetch origin "$TARGET_BRANCH"
  git checkout -b "$BRANCH" "origin/${TARGET_BRANCH}"

  # -m 1 handles a real merge commit; plain cherry-pick handles a squash merge.
  if ! { git cherry-pick -x -m 1 "$MERGE_SHA" 2>/dev/null || git cherry-pick -x "$MERGE_SHA"; }; then
    echo "error: ${MERGE_SHA} did not cherry-pick cleanly onto ${TARGET_BRANCH}." >&2
    echo "Resolve the conflicts, 'git add' them, then re-run:" >&2
    echo "  $0 ${PR_NUMBER} ${TARGET_VERSION} --continue" >&2
    exit 1
  fi
fi

title="backport v${TARGET_VERSION}: ${PR_TITLE}"
body=$(printf 'Backport from #%s to release v%s\n\n---\n\n%s' \
  "$PR_NUMBER" "$TARGET_VERSION" "$PR_BODY")

# Highest open milestone matching v<version>.* (e.g. v1.11.1), if any.
MILESTONE=$(gh api "repos/{owner}/{repo}/milestones?state=open" \
  --jq ".[].title | select(startswith(\"v${TARGET_VERSION}.\"))" \
  | sort -V | tail -n1)
milestone_args=()
if [ -n "$MILESTONE" ]; then
  milestone_args=(--milestone "$MILESTONE")
else
  echo "warning: no open milestone matching v${TARGET_VERSION}.* found; PR will have no milestone" >&2
fi

echo
echo "About to run:"
printf '  git push -u --force-with-lease origin %q\n' "$BRANCH"
printf '  gh pr create --base %q --head %q --title %q --body %q' \
  "$TARGET_BRANCH" "$BRANCH" "$title" "$body"
[ -n "$MILESTONE" ] && printf ' --milestone %q' "$MILESTONE"
printf '\n'
echo
read -r -p "Open this pull request? [y/N] " reply
case "$reply" in
  [yY] | [yY][eE][sS]) ;;
  *) echo "Aborted. The cherry-pick is on local branch ${BRANCH}; push it manually if desired."; exit 0 ;;
esac

git push -u --force-with-lease origin "$BRANCH"

gh pr create \
  --base "$TARGET_BRANCH" \
  --head "$BRANCH" \
  --title "$title" \
  --body "$body" \
  ${milestone_args[@]+"${milestone_args[@]}"}

# The backport now exists, so drop the label that flagged this PR for one.
gh pr edit "$PR_NUMBER" --remove-label needs-backport

# Switch back to the original branch we were on before doing the backport
git checkout -
