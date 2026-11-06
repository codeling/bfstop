#!/bin/bash
#
# Builds the release zips of BFStop: the plugin (this repository), the
# component (a checkout of codeling/com_bfstop) and the package containing
# both, which is what users install. The checkouts are not changed; the zips
# go to the output directory (default: build/ in this repository):
#
#   bfstop-<version>.zip, com_bfstop-<version>.zip, pkg_bfstop-<version>.zip
#
# All three must have the same version (see tests/lint/check-versions.php),
# so a package can't contain the extensions of another release.
#
# Usage: package/build.sh <com_bfstop checkout> [<output directory>]
set -euo pipefail

plugin_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
component_root="$(cd "${1:?usage: package/build.sh <com_bfstop checkout> [<output directory>]}" && pwd)"
out="${2:-$plugin_root/build}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

COM_BFSTOP_ROOT="$component_root" php "$plugin_root/tests/lint/check-versions.php"
version="$(php "$plugin_root/tests/lint/check-versions.php" --print-version)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# each extension is zipped by its own deploy.sh, in a copy of its checkout
# (deploy.sh writes the zip next to its sources)
build_extension() {
	local src="$1" zip="$2"
	mkdir -p "$work/src"
	rm -rf "$work/src/ext"
	cp -a "$src" "$work/src/ext"
	rm -f "$work/src/ext"/*.zip
	(cd "$work/src/ext" && ./deploy.sh zip > /dev/null)
	mv "$work/src/ext/$zip" "$out/$zip"
	php "$plugin_root/tests/lint/check-zip.php" "$out/$zip" bfstop.xml > /dev/null
}
build_extension "$plugin_root" "bfstop-$version.zip"
build_extension "$component_root" "com_bfstop-$version.zip"

mkdir -p "$work/pkg/packages"
cp "$plugin_root/package/pkg_bfstop.xml" "$plugin_root/package/script.php" "$work/pkg/"
cp "$out/bfstop-$version.zip" "$work/pkg/packages/plg_sys_bfstop.zip"
cp "$out/com_bfstop-$version.zip" "$work/pkg/packages/com_bfstop.zip"
rm -f "$out/pkg_bfstop-$version.zip"
(cd "$work/pkg" && zip -qr "$out/pkg_bfstop-$version.zip" pkg_bfstop.xml script.php packages)
php "$plugin_root/tests/lint/check-zip.php" "$out/pkg_bfstop-$version.zip" pkg_bfstop.xml > /dev/null

(cd "$out" && sha256sum "bfstop-$version.zip" "com_bfstop-$version.zip" "pkg_bfstop-$version.zip" > "SHA256SUMS-$version")
echo "Built in $out:"
cat "$out/SHA256SUMS-$version"
