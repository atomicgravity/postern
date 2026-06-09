#!/usr/bin/env bash
# Developer ID-signs and notarizes a macOS binary in place. Called as a
# GoReleaser post-build hook (per built binary) before the binary is archived,
# so the published tarball carries the signed + notarized executable.
#
# No-ops for non-darwin targets. Skips, with a warning, when the signing
# secrets are absent — an unconfigured repo or a fork still publishes a release
# (unsigned) rather than failing it. quill reads the cert + notary credentials
# from QUILL_* env vars (set on the GoReleaser step in the release workflow).
set -euo pipefail

binary="${1:?usage: sign-macos.sh <binary-path> <goos>}"
goos="${2:?usage: sign-macos.sh <binary-path> <goos>}"

if [ "${goos}" != "darwin" ]; then
  exit 0
fi

if [ -z "${QUILL_SIGN_P12:-}" ] || [ -z "${QUILL_NOTARY_KEY:-}" ]; then
  echo "sign-macos: signing secrets unset — leaving ${binary} unsigned" >&2
  exit 0
fi

echo "sign-macos: signing + notarizing ${binary}"
quill sign-and-notarize "${binary}"
