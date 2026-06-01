#!/usr/bin/env bash
# TAK-8 / F-SEC-4 — Build-time guard: the .git/ directory must never be published.
#
# Cloudflare Pages does not publish .git/ by default and .wranglerignore also excludes it,
# but this assertion makes the guarantee explicit and CI-enforceable. Run it against the
# directory that will be uploaded as the Pages output (defaults to the repo root / ".").
#
# Usage:
#   scripts/assert-no-git-published.sh [PUBLISH_DIR]
# Exits non-zero if a .git directory (or a stray .git/config|HEAD) is present in PUBLISH_DIR.
set -euo pipefail

PUBLISH_DIR="${1:-.}"

fail() { echo "FAIL: $*" >&2; exit 1; }

if [ ! -d "$PUBLISH_DIR" ]; then
  fail "publish dir '$PUBLISH_DIR' does not exist"
fi

# A real git working tree at the repo root is fine for local dev — what must never happen is
# .git/ ending up inside an isolated publish/output directory that gets uploaded.
# When PUBLISH_DIR is the repo root we only verify .wranglerignore excludes .git/.
if [ "$PUBLISH_DIR" = "." ] || [ "$PUBLISH_DIR" = "./" ]; then
  if [ ! -f .wranglerignore ]; then
    fail ".wranglerignore missing — cannot guarantee .git/ is excluded from Pages upload"
  fi
  if ! grep -Eq '(^|/)\.git/?($|\*)' .wranglerignore; then
    fail ".wranglerignore does not exclude .git/ — add a '.git/' entry"
  fi
  echo "OK: .wranglerignore excludes .git/ from the Cloudflare Pages upload."
  exit 0
fi

# For an explicit isolated output dir, the .git directory must be physically absent.
if find "$PUBLISH_DIR" -name '.git' -maxdepth 3 -print -quit | grep -q .; then
  fail ".git directory found inside publish dir '$PUBLISH_DIR'"
fi
if find "$PUBLISH_DIR" -path '*/.git/config' -o -path '*/.git/HEAD' 2>/dev/null | grep -q .; then
  fail "git metadata (.git/config or .git/HEAD) found inside publish dir '$PUBLISH_DIR'"
fi

echo "OK: no .git/ metadata present in publish dir '$PUBLISH_DIR'."
