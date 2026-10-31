#!/bin/sh
# Commit the regenerated lists and feed state (CI only). No-op when nothing
# changed. Pushing is done by the workflow.
set -eu

now=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
git add blocklist*.txt blocklist*.rsc blocklist*.json tor_blocklist.* feed_state.json
git status
if ! git diff --cached --quiet; then
    # Identity via -c, not git config: nothing persists in the repo's config
    # (a worktree shares it). --no-verify: the local pre-commit hook refuses
    # generated files by design.
    git -c user.name="GitHub Actions" -c user.email="noreply@github.actions.bot" \
        commit --no-verify -m "Regenerate blocklists - $now"
fi
