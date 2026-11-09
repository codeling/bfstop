#!/usr/bin/env bash
#
# Sets up a Joomla site with bfstop installed, for the integration tests:
# downloads the Joomla full package (unless $JOOMLA_ROOT already contains a
# not yet installed Joomla), runs Joomla's CLI installer against the given
# database, and installs bfstop through Joomla's extension installer - the
# way users install it:
#
#   - $BFSTOP_PACKAGE set: that package zip (e.g. the one CI built, or the
#     previous release for the upgrade test)
#   - else, with $COM_BFSTOP_ROOT: the package built from the checkouts by
#     package/build.sh
#   - else: only the plugin, zipped by its deploy.sh
#
# Environment:
#   JOOMLA_VERSION   Joomla version to download, e.g. 5.4.8
#   JOOMLA_ROOT      directory to set up the site in
#   DB_TYPE          mysqli or pgsql
#   DB_HOST, DB_USER, DB_PASS, DB_NAME   database connection (database must exist)
#   COM_BFSTOP_ROOT  optional: checkout of https://github.com/codeling/com_bfstop
#   BFSTOP_PACKAGE   optional: package zip to install instead of building one
#   DOWNLOAD_CACHE   optional: directory to keep the Joomla package in between
#                    runs, see download-joomla.sh
set -euo pipefail

: "${JOOMLA_ROOT:?}" "${DB_TYPE:?}" "${DB_HOST:?}" "${DB_USER:?}" "${DB_NAME:?}"
plugin_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="$(mktemp -d)"

if [ ! -f "$JOOMLA_ROOT/index.php" ]; then
	: "${JOOMLA_VERSION:?}"
	# verifies the package against tests/ci/joomla-checksums.sha256
	"$plugin_root/tests/ci/download-joomla.sh" "$JOOMLA_VERSION" "$JOOMLA_ROOT"
fi

echo "Installing Joomla ($DB_TYPE on $DB_HOST)"
# the admin username deliberately differs from "admin" only in case, see
# ComponentTest::testWarnsAboutAdminUserCaseInsensitively
php "$JOOMLA_ROOT/installation/joomla.php" install -n \
	--site-name="bfstop tests" \
	--admin-user="Test Admin" --admin-username=Admin \
	--admin-password=bfstop-test-password --admin-email=admin@example.org \
	--db-type="$DB_TYPE" --db-host="$DB_HOST" --db-user="$DB_USER" \
	--db-pass="${DB_PASS:-}" --db-name="$DB_NAME" --db-prefix=jos_ \
	--db-encryption=0 --public-folder=""

install_zip() {
	echo "Installing $(basename "$1")"
	php "$JOOMLA_ROOT/cli/joomla.php" extension:install --path="$1" -n
}

if [ -n "${BFSTOP_PACKAGE:-}" ]; then
	install_zip "$BFSTOP_PACKAGE"
elif [ -n "${COM_BFSTOP_ROOT:-}" ]; then
	"$plugin_root/package/build.sh" "$COM_BFSTOP_ROOT" "$build_dir" > /dev/null
	install_zip "$build_dir"/pkg_bfstop-*.zip
else
	(cd "$plugin_root" && ./deploy.sh zip > /dev/null && mv bfstop-*.zip "$build_dir/")
	install_zip "$build_dir"/bfstop-*.zip
fi
rm -rf "$build_dir"
