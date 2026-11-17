#!/bin/bash
#
# Builds the release zips of BFStop from this repository: the system plugin
# (plugin/), the task plugin (task/), the component (component/) and the
# package containing all three, which is what users install. The checkout is
# not changed; the zips go to the output directory (default: build/):
#
#   bfstop-<version>.zip, plg_task_bfstop-<version>.zip,
#   com_bfstop-<version>.zip, pkg_bfstop-<version>.zip
#
# All of them must have the same version (see tests/lint/check-versions.php),
# so a package can't contain the extensions of another release.
#
# Usage: package/build.sh [<output directory>]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$root/build}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

php "$root/tests/lint/check-versions.php"
version="$(php "$root/tests/lint/check-versions.php" --print-version)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# plugin and component are zipped by their own deploy.sh, in a copy of their
# directories (deploy.sh writes the zip next to its sources; the plugin's
# takes the documentation from the top directory)
mkdir -p "$work/src"
cp -a "$root/plugin" "$root/component" "$root/CHANGELOG" "$root/LICENSE.txt" "$root/README.md" "$work/src/"
build_extension() {
	local dir="$1" zip="$2"
	rm -f "$work/src/$dir"/*.zip
	(cd "$work/src/$dir" && ./deploy.sh zip > /dev/null)
	mv "$work/src/$dir/$zip" "$out/$zip"
	php "$root/tests/lint/check-zip.php" "$out/$zip" bfstop.xml > /dev/null
}
build_extension plugin "bfstop-$version.zip"
build_extension component "com_bfstop-$version.zip"

# the task plugin is the directory task/, with its own manifest
rm -f "$out/plg_task_bfstop-$version.zip"
(cd "$root/task" && zip -qr "$out/plg_task_bfstop-$version.zip" bfstop.xml index.html script.php services src language)
php "$root/tests/lint/check-zip.php" "$out/plg_task_bfstop-$version.zip" bfstop.xml > /dev/null

mkdir -p "$work/pkg/packages"
cp "$root/package/pkg_bfstop.xml" "$root/package/script.php" "$work/pkg/"
cp "$out/bfstop-$version.zip" "$work/pkg/packages/plg_sys_bfstop.zip"
cp "$out/plg_task_bfstop-$version.zip" "$work/pkg/packages/plg_task_bfstop.zip"
cp "$out/com_bfstop-$version.zip" "$work/pkg/packages/com_bfstop.zip"
rm -f "$out/pkg_bfstop-$version.zip"
(cd "$work/pkg" && zip -qr "$out/pkg_bfstop-$version.zip" pkg_bfstop.xml script.php packages)
php "$root/tests/lint/check-zip.php" "$out/pkg_bfstop-$version.zip" pkg_bfstop.xml > /dev/null

(cd "$out" && sha256sum "bfstop-$version.zip" "plg_task_bfstop-$version.zip" "com_bfstop-$version.zip" "pkg_bfstop-$version.zip" > "SHA256SUMS-$version")
echo "Built in $out:"
cat "$out/SHA256SUMS-$version"
