#!/usr/bin/env bash
#
# Tests the update from the previous release (tests/ci/previous-release.sha256)
# to the package in $BFSTOP_PACKAGE, the way a site is updated: sets up a
# Joomla site with the previous release, gives it settings and data in the
# form that version kept them (tests/Upgrade/fixtures/seed.php), installs the
# new package over it and runs the "upgrade" test suite on the result.
#
# Environment: as for install-joomla.sh (the database must be MySQL/MariaDB:
# PostgreSQL is supported from 2.0.0 on), plus
#   BFSTOP_PACKAGE   the package zip to update to
#   COM_BFSTOP_ROOT  checkout of com_bfstop (the tests load its classes)
#   PHPUNIT          optional: the phpunit command (default: phpunit)
#   DOWNLOAD_CACHE   optional: directory to take the previous release and the
#                    Joomla package from and keep them in, see fetch-verified.sh
set -euo pipefail

: "${BFSTOP_PACKAGE:?}" "${JOOMLA_ROOT:?}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plugin_root="$(cd "$here/../.." && pwd)"
new_package="$(cd "$(dirname "$BFSTOP_PACKAGE")" && pwd)/$(basename "$BFSTOP_PACKAGE")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

read -r expected file < <(grep -v '^#' "$here/previous-release.sha256" | grep . | head -n 1)
previous="${file#pkg_bfstop-}"
previous="${previous%.zip}"
echo "Fetching BFStop $previous"
# from the download cache if there is one (DOWNLOAD_CACHE), see fetch-verified.sh
"$here/fetch-verified.sh" "https://github.com/codeling/bfstop/releases/download/$previous/$file" \
	"$expected" "$work/$file"

BFSTOP_PACKAGE="$work/$file" "$here/install-joomla.sh"
php "$plugin_root/tests/Upgrade/fixtures/seed.php"

echo "Updating to $(basename "$new_package")"
php "$JOOMLA_ROOT/cli/joomla.php" extension:install --path="$new_package" -n | tee "$work/update.log"

UPGRADE_FROM="$previous" UPGRADE_LOG="$work/update.log" BFSTOP_PACKAGE="$new_package" \
	"${PHPUNIT:-phpunit}" -c "$plugin_root/tests/phpunit.xml.dist" --testsuite upgrade
