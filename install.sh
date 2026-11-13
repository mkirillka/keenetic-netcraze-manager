#!/usr/bin/env bash
# Install this skill as a symlink so `git pull` keeps the installed copy fresh.
#
#   ./install.sh                         # -> ~/.config/opencode/skills/keenetic-netcraze-manager
#   ./install.sh --dest ~/.agents/skills # -> ~/.agents/skills/keenetic-netcraze-manager
#   ./install.sh --dry-run               # show what would happen

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="$(basename "$SRC")"
DEST_ROOT="${OPENCODE_SKILLS_DIR:-$HOME/.config/opencode/skills}"

DRY_RUN=0
FORCE=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [--dry-run] [--force] [--dest <dir>]

  --dry-run     show what would be done and exit
  --force       replace whatever already sits at the target path
  --dest <dir>  install root (default: $OPENCODE_SKILLS_DIR or ~/.config/opencode/skills)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --force)   FORCE=1; shift ;;
    --dest)
      if [[ -z "${2:-}" ]]; then echo "--dest needs a directory" >&2; exit 2; fi
      DEST_ROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

# expand a leading ~ so the user can pass --dest ~/.agents/skills
DEST_ROOT="${DEST_ROOT/#\~/$HOME}"
TARGET="$DEST_ROOT/$NAME"

mkdir -p "$DEST_ROOT"

if [[ -L "$TARGET" ]]; then
  if [[ "$(readlink "$TARGET")" == "$SRC" ]]; then
    echo "= already installed: $TARGET"
    exit 0
  fi
fi

if [[ -e "$TARGET" || -L "$TARGET" ]]; then
  if [[ $FORCE -eq 0 ]]; then
    echo "! something already exists at $TARGET — skipping (use --force to replace)" >&2
    exit 1
  fi
  echo "~ removing $TARGET"
  [[ $DRY_RUN -eq 0 ]] && rm -rf "$TARGET"
fi

echo "+ $TARGET -> $SRC"
if [[ $DRY_RUN -eq 0 ]]; then
  ln -s "$SRC" "$TARGET"
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo "dry run: nothing changed"
else
  echo "done. Restart your agent runtime so the skill shows up."
  echo "next: python3 \"$TARGET/scripts/kn.py\" init"
fi
