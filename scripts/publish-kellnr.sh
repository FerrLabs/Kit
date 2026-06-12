#!/usr/bin/env bash
# Publish every FerrFlow-managed workspace crate to the Kellnr registry,
# skipping any version already uploaded. Runs after FerrFlow has versioned
# and tagged the crates, so a fresh version bump lands on the registry in the
# same release.
#
# --no-verify: the workspace is already built and tested by the CI workflow;
# the publish-time verify build would otherwise need each just-published crate
# to propagate to the sparse index before the next dependent crate could
# resolve it. Skipping it makes the batch publish order-independent.
#
# Requires CARGO_REGISTRIES_KELLNR_TOKEN in the environment.
set -euo pipefail

cd "$(dirname "$0")/.."

crates=$(grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]+"' ferrflow.json \
  | sed -E 's/.*"([^"]+)"[[:space:]]*$/\1/')

failed=()
for crate in $crates; do
  echo "::group::publish ${crate}"
  if out=$(cargo publish -p "$crate" --registry kellnr --no-verify 2>&1); then
    echo "$out"
    echo "published ${crate}"
  elif printf '%s\n' "$out" | grep -qiE 'already (uploaded|exists)'; then
    echo "$out"
    echo "${crate}: this version is already on Kellnr — skipping"
  else
    echo "$out"
    echo "::error::failed to publish ${crate}"
    failed+=("$crate")
  fi
  echo "::endgroup::"
done

if [ ${#failed[@]} -gt 0 ]; then
  echo "::error::publish failed for: ${failed[*]}"
  exit 1
fi
