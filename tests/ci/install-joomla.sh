#!/usr/bin/env bash
#
# Sets up a Joomla site with bfstop installed, for the integration tests:
# downloads the Joomla full package (unless $JOOMLA_ROOT already contains a
# not yet installed Joomla), runs Joomla's CLI installer against the given
# database, and installs the plugin (and, if $COM_BFSTOP_ROOT is set, the
# component) from the source checkouts through Joomla's extension installer.
#
# Environment:
#   JOOMLA_VERSION   Joomla version to download, e.g. 5.4.8
#   JOOMLA_ROOT      directory to set up the site in
#   DB_TYPE          mysqli or pgsql
#   DB_HOST, DB_USER, DB_PASS, DB_NAME   database connection (database must exist)
#   COM_BFSTOP_ROOT  optional: checkout of https://github.com/codeling/com_bfstop
set -euo pipefail

: "${JOOMLA_ROOT:?}" "${DB_TYPE:?}" "${DB_HOST:?}" "${DB_USER:?}" "${DB_NAME:?}"
plugin_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="$(mktemp -d)"

if [ ! -f "$JOOMLA_ROOT/index.php" ]; then
	: "${JOOMLA_VERSION:?}"
	echo "Downloading Joomla $JOOMLA_VERSION"
	mkdir -p "$JOOMLA_ROOT"
	curl -fsSL "https://github.com/joomla/joomla-cms/releases/download/$JOOMLA_VERSION/Joomla_$JOOMLA_VERSION-Stable-Full_Package.tar.gz" \
		| tar -xz -C "$JOOMLA_ROOT"
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

install_extension() {
	local src="$1" zip="$build_dir/$2.zip"
	(cd "$src" && zip -qr "$zip" . -x '.git/*' '.github/*' 'tests/*')
	echo "Installing $2"
	php "$JOOMLA_ROOT/cli/joomla.php" extension:install --path="$zip" -n
}

install_extension "$plugin_root" plg_system_bfstop
if [ -n "${COM_BFSTOP_ROOT:-}" ]; then
	install_extension "$COM_BFSTOP_ROOT" com_bfstop
fi
rm -rf "$build_dir"
