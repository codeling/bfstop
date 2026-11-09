#!/usr/bin/env bash
#
# Downloads a Joomla! full package from the GitHub release, verifies its SHA-256
# against tests/ci/joomla-checksums.sha256 and only then unpacks it. What the
# integration tests install and run is code from this download, so it must be
# the package that was checked, not whatever the network delivered.
#
# Usage: download-joomla.sh VERSION TARGET_DIR
#
# Environment:
#   JOOMLA_SHA256   the expected SHA-256 of a version which is not listed in the
#                   checksum file (for trying a version locally)
#   DOWNLOAD_CACHE  optional: directory to take the package from (if it has
#                   the expected SHA-256) and to keep it in, see fetch-verified.sh
set -euo pipefail

version="${1:?usage: download-joomla.sh VERSION TARGET_DIR}"
target="${2:?usage: download-joomla.sh VERSION TARGET_DIR}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
package="Joomla_${version}-Stable-Full_Package.tar.gz"

expected="${JOOMLA_SHA256:-$(awk -v f="$package" '!/^#/ && $2 == f { print $1 }' "$here/joomla-checksums.sha256")}"
if [ -z "$expected" ]; then
	echo "No SHA-256 known for $package: add it to tests/ci/joomla-checksums.sha256" >&2
	echo "(see the comment there for how to check it), or set JOOMLA_SHA256." >&2
	exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
echo "Fetching Joomla $version"
# from the download cache if there is one (DOWNLOAD_CACHE), see fetch-verified.sh
"$here/fetch-verified.sh" "https://github.com/joomla/joomla-cms/releases/download/$version/$package" \
	"$expected" "$work/$package"
mkdir -p "$target"
tar -xzf "$work/$package" -C "$target"
echo "Joomla $version unpacked into $target (SHA-256 verified)"
