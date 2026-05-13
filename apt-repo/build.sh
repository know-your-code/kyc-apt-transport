#!/usr/bin/env bash
# Build (and optionally sign) the kyc apt repository metadata from a
# pool of .debs.
#
# Inputs (all required unless noted):
#   $POOL_DIR         existing pool laid out as <pool>/main/k/kyc/*.deb
#                     (and main/<initial>/<name>/...). Defaults to ./pool.
#   $OUT_DIR          where Release / InRelease / Packages live afterwards.
#                     Defaults to ./out.
#   $SUITE            apt suite name. Defaults to `stable`.
#   $COMPONENTS       space-separated components. Defaults to `main`.
#   $ARCHITECTURES    space-separated arch list. Defaults to `amd64 arm64`.
#   $ORIGIN, $LABEL   shown in apt's update output. Default `kyc`.
#   $VALID_DAYS       Valid-Until window for Release. Default 30.
#
# Optional signing inputs (set --sign to enable):
#   $GNUPGHOME                          tmpfs path; auto-created if absent
#   $APT_SIGNING_SUBKEY_ASC_BASE64      base64-encoded armored secret subkey
#                                       (symmetric-encrypted with the
#                                       passphrase below)
#   $APT_SIGNING_SUBKEY_PASSPHRASE      symmetric-decryption passphrase
#
# Local-dev usage:
#   ./apt-repo/build.sh --no-sign           # metadata only, no GPG
#   ./apt-repo/build.sh --sign \
#       --keyring=/tmp/throwaway-gpg \
#       --signing-key=<fpr>                 # for end-to-end local testing
#                                           # with a key NOT used in prod
#
# CI usage:
#   ./apt-repo/build.sh --sign --ci         # reads env vars listed above

set -euo pipefail

# ── arg parsing ─────────────────────────────────────────────────────────────

SIGN=0
CI_MODE=0
LOCAL_KEYRING=""
LOCAL_SIGNING_KEY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sign)            SIGN=1; shift ;;
    --no-sign)         SIGN=0; shift ;;
    --ci)              CI_MODE=1; shift ;;
    --keyring=*)       LOCAL_KEYRING="${1#*=}"; shift ;;
    --signing-key=*)   LOCAL_SIGNING_KEY="${1#*=}"; shift ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 1
      ;;
  esac
done

# ── inputs with defaults ───────────────────────────────────────────────────

POOL_DIR="${POOL_DIR:-./pool}"
OUT_DIR="${OUT_DIR:-./out}"
SUITE="${SUITE:-stable}"
COMPONENTS="${COMPONENTS:-main}"
ARCHITECTURES="${ARCHITECTURES:-amd64 arm64}"
ORIGIN="${ORIGIN:-kyc}"
LABEL="${LABEL:-kyc}"
VALID_DAYS="${VALID_DAYS:-30}"

if [[ ! -d "$POOL_DIR" ]]; then
  echo "error: POOL_DIR '$POOL_DIR' doesn't exist" >&2
  exit 1
fi

# ── sanity-check apt-ftparchive is present ─────────────────────────────────

if ! command -v apt-ftparchive >/dev/null 2>&1; then
  echo "error: apt-ftparchive is required (apt-utils package on Debian/Ubuntu)" >&2
  exit 1
fi

# ── lay out dists/ tree, generate Packages per arch ────────────────────────

DISTS="$OUT_DIR/dists/$SUITE"
rm -rf "$DISTS"
mkdir -p "$DISTS"

# Symlink the pool into OUT_DIR so apt-ftparchive emits filenames
# relative to the apt root (pool/main/k/kyc/...) rather than to
# POOL_DIR. apt clients fetch via `pool/...` relative to the suite root.
rm -rf "$OUT_DIR/pool"
ln -sfn "$(cd "$POOL_DIR" && pwd)" "$OUT_DIR/pool"

for arch in $ARCHITECTURES; do
  for component in $COMPONENTS; do
    arch_dir="$DISTS/$component/binary-$arch"
    mkdir -p "$arch_dir"

    # apt-ftparchive packages walks the pool and emits a Packages
    # stanza per .deb, with size + checksums + Description.
    # --arch limits to one arch's .debs in this pool.
    (cd "$OUT_DIR" && apt-ftparchive --arch="$arch" packages "pool/$component") \
      > "$arch_dir/Packages"
    gzip -9 -kf "$arch_dir/Packages"
  done
done

# ── generate Release file ──────────────────────────────────────────────────

CONF=$(mktemp)
trap 'rm -f "$CONF"' EXIT

# apt-ftparchive's release config — describes what the Release file
# should declare. Architecture/Component lists must match what we
# emitted above or apt clients refuse the index.
cat > "$CONF" <<EOF
APT::FTPArchive::Release::Origin "$ORIGIN";
APT::FTPArchive::Release::Label "$LABEL";
APT::FTPArchive::Release::Suite "$SUITE";
APT::FTPArchive::Release::Codename "$SUITE";
APT::FTPArchive::Release::Architectures "$ARCHITECTURES";
APT::FTPArchive::Release::Components "$COMPONENTS";
APT::FTPArchive::Release::Description "kyc apt repository";
EOF

# apt-ftparchive emits a Date line itself. We want to add Valid-Until
# without duplicating Date; insert it right after Date via sed.
# 30 days is the standard window for static releases re-signed
# monthly (RFC 2822 / UTC formatting).
UNTIL="$(date -u -R -d "+${VALID_DAYS} days" 2>/dev/null \
  || date -u -v "+${VALID_DAYS}d" -R)"   # macOS fallback for local testing

(cd "$OUT_DIR" && apt-ftparchive -c="$CONF" release "dists/$SUITE") \
  | sed "/^Date:/ a Valid-Until: $UNTIL" \
  > "$DISTS/Release"

# ── optional GPG signing ───────────────────────────────────────────────────

if [[ "$SIGN" == "1" ]]; then
  case "$CI_MODE" in
    1)
      : "${APT_SIGNING_SUBKEY_ASC_BASE64:?APT_SIGNING_SUBKEY_ASC_BASE64 required in --ci mode}"
      : "${APT_SIGNING_SUBKEY_PASSPHRASE:?APT_SIGNING_SUBKEY_PASSPHRASE required in --ci mode}"
      GNUPGHOME="${GNUPGHOME:-$(mktemp -d)}"
      export GNUPGHOME
      chmod 700 "$GNUPGHOME"
      # Decrypt the symmetric envelope, then import the inner secret
      # subkey. The passphrase that unlocks the subkey itself is the
      # same symmetric passphrase by convention (the ceremony script
      # uses one passphrase for both layers — simpler to manage).
      echo "$APT_SIGNING_SUBKEY_ASC_BASE64" \
        | base64 -d \
        | gpg --batch --pinentry-mode loopback \
              --passphrase "$APT_SIGNING_SUBKEY_PASSPHRASE" \
              --decrypt \
        | gpg --batch --pinentry-mode loopback \
              --passphrase "$APT_SIGNING_SUBKEY_PASSPHRASE" \
              --import
      GPG_FLAGS=(--batch --pinentry-mode loopback
                 --passphrase "$APT_SIGNING_SUBKEY_PASSPHRASE")
      ;;
    0)
      if [[ -z "$LOCAL_KEYRING" || -z "$LOCAL_SIGNING_KEY" ]]; then
        echo "error: --sign without --ci requires --keyring= and --signing-key=" >&2
        exit 1
      fi
      export GNUPGHOME="$LOCAL_KEYRING"
      GPG_FLAGS=()
      ;;
  esac

  # SHA256 is the floor for modern apt-secure; SHA1/MD5 defaults from
  # older GnuPG were dropped in apt 2.4+.
  gpg "${GPG_FLAGS[@]}" --digest-algo SHA256 \
      --output "$DISTS/Release.gpg" \
      --detach-sign "$DISTS/Release"
  gpg "${GPG_FLAGS[@]}" --digest-algo SHA256 \
      --output "$DISTS/InRelease" \
      --clearsign "$DISTS/Release"
fi

echo
echo "Built apt repo metadata:"
find "$DISTS" -type f | sort
