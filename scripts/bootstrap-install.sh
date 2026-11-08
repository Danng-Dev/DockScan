#!/usr/bin/env bash
# Hosted DockScan bootstrap installer.
# Intended usage:
# curl -fsSL https://example.invalid/dockscan/bootstrap-install.sh | bash -s -- \
#   --repository https://github.com/ORG/DockScan.git --ref v0.1.0 --verify-tag
set -euo pipefail

REPOSITORY="${DOCKSCAN_REPOSITORY:-}"
REF="${DOCKSCAN_REF:-}"
VERIFY_TAG=0
INSTALL_ARGS=()

usage() {
  cat <<'EOF'
Usage: bootstrap-install.sh --repository HTTPS_GIT_URL --ref TAG_OR_COMMIT [options]

Required:
  --repository URL       HTTPS Git repository URL
  --ref REF              Immutable release tag or commit SHA

Verification:
  --verify-tag           Require `git verify-tag` to validate the selected tag

Install options are passed through to install.sh:
  --service, --prefix PATH, --bin-dir PATH, --user NAME

Security: do not install from a floating branch such as main. Prefer a signed
release tag, import the publisher's Git signing key first, and use --verify-tag.
EOF
}

while (($#)); do
  case "$1" in
    --repository) REPOSITORY=${2:?missing repository}; shift 2 ;;
    --ref) REF=${2:?missing ref}; shift 2 ;;
    --verify-tag) VERIFY_TAG=1; shift ;;
    --service) INSTALL_ARGS+=(--service); shift ;;
    --prefix|--bin-dir|--user) INSTALL_ARGS+=("$1" "${2:?missing value}"); shift 2 ;;
    --help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$REPOSITORY" && -n "$REF" ]] || { usage >&2; exit 2; }
[[ "$REPOSITORY" =~ ^https:// ]] || { echo "Only HTTPS repository URLs are accepted." >&2; exit 2; }
command -v git >/dev/null || { echo "git is required." >&2; exit 1; }

WORK_DIR="$(mktemp -d -t dockscan-install.XXXXXXXX)"
cleanup() { rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT INT TERM

git -C "$WORK_DIR" init -q
git -C "$WORK_DIR" remote add origin "$REPOSITORY"
git -C "$WORK_DIR" fetch -q --depth=1 origin "$REF"
git -C "$WORK_DIR" checkout -q --detach FETCH_HEAD

if (( VERIFY_TAG )); then
  [[ "$REF" != "$(git -C "$WORK_DIR" rev-parse HEAD)" ]] || {
    echo "--verify-tag requires a tag name, not only a commit SHA." >&2; exit 2;
  }
  git -C "$WORK_DIR" fetch -q --tags --depth=1 origin "refs/tags/$REF:refs/tags/$REF"
  git -C "$WORK_DIR" verify-tag "$REF"
fi

echo "Installing DockScan commit $(git -C "$WORK_DIR" rev-parse HEAD) from $REPOSITORY"
if [[ $EUID -eq 0 ]]; then
  bash "$WORK_DIR/install.sh" "${INSTALL_ARGS[@]}"
else
  sudo bash "$WORK_DIR/install.sh" "${INSTALL_ARGS[@]}"
fi
