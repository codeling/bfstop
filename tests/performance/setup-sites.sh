#!/usr/bin/env bash
#
# Sets up the Joomla sites the performance comparison runs against: three
# sites on the same Joomla version, PHP and database server, differing only
# in the bfstop plugin installed in them:
#
#   none     no bfstop at all - the baseline the footprint is measured against
#   baseline the plugin as released in $BASELINE_REF (default: tag 1.5.2)
#   current  the plugin as in $CURRENT_REF (default: HEAD)
#
# Each plugin is installed from the release zip its own deploy.sh builds (so
# the package, not the source tree, is what gets compared), through Joomla's
# CLI extension installer.
#
# Environment:
#   JOOMLA_VERSION   Joomla to install in all sites (default 5.4.8: both the
#                    old plugin and the current one run on it)
#   BENCH_DIR        working directory (default /tmp/bfstop-perf); the sites
#                    are created in $BENCH_DIR/sites/<name>. Existing sites
#                    are kept, delete the directory to start over.
#   DB_HOST, DB_USER, DB_PASS   MySQL/MariaDB connection; the user must be
#                    allowed to (re)create databases named bfperf_<name>.
#                    These databases are DROPPED and recreated.
#   BASELINE_REF, CURRENT_REF   git refs of the plugin checkout to compare
#
# Writes $BENCH_DIR/sites.json for bench.php.
set -euo pipefail

: "${DB_HOST:=127.0.0.1}" "${DB_USER:=root}" "${DB_PASS:=}"
: "${JOOMLA_VERSION:=5.4.8}" "${BENCH_DIR:=/tmp/bfstop-perf}"
: "${BASELINE_REF:=1.5.2}" "${CURRENT_REF:=HEAD}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$BENCH_DIR/sites" "$BENCH_DIR/packages"

sql() {
	mysql -h"$DB_HOST" -u"$DB_USER" ${DB_PASS:+-p"$DB_PASS"} "$@"
}

# builds the release zip of a git ref using the deploy.sh of that very ref
build_package() {
	local ref="$1" name="$2" tmp
	tmp="$(mktemp -d)"
	git -C "$repo" fetch --quiet origin "refs/tags/$ref:refs/tags/$ref" 2>/dev/null || true
	git -C "$repo" archive "$ref" | tar -x -C "$tmp"
	(cd "$tmp" && ./deploy.sh zip > /dev/null)
	cp "$tmp"/bfstop-*.zip "$BENCH_DIR/packages/$name.zip"
	rm -rf "$tmp"
}

install_joomla() {
	local name="$1" dir="$BENCH_DIR/sites/$1" db="bfperf_$1"
	local tarball="$BENCH_DIR/joomla-$JOOMLA_VERSION.tar.gz"
	if [ -f "$dir/configuration.php" ]; then
		echo "Site $name already exists, keeping it"
		return
	fi
	if [ ! -f "$tarball" ]; then
		echo "Downloading Joomla $JOOMLA_VERSION"
		curl -fsSL -o "$tarball" "https://github.com/joomla/joomla-cms/releases/download/$JOOMLA_VERSION/Joomla_$JOOMLA_VERSION-Stable-Full_Package.tar.gz"
	fi
	rm -rf "$dir"
	mkdir -p "$dir"
	tar -xz -C "$dir" -f "$tarball"
	sql -e "DROP DATABASE IF EXISTS $db; CREATE DATABASE $db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
	echo "Installing Joomla $JOOMLA_VERSION as site '$name'"
	php "$dir/installation/joomla.php" install -n \
		--site-name="bfstop perf $name" \
		--admin-user="Perf Admin" --admin-username=perfadmin \
		--admin-password=bfstop-perf-password --admin-email=admin@example.org \
		--db-type=mysqli --db-host="$DB_HOST" --db-user="$DB_USER" \
		--db-pass="$DB_PASS" --db-name="$db" --db-prefix=jos_ \
		--db-encryption=0 --public-folder="" > /dev/null
	# PHP's built-in web server has no URL rewriting, and Joomla's SEF
	# redirects don't get along with it: use the plain index.php?option=... URLs
	sed -i 's/public \$sef = true;/public $sef = false;/' "$dir/configuration.php"
}

install_plugin() {
	local name="$1" dir="$BENCH_DIR/sites/$1"
	echo "Installing the bfstop package into site '$name'"
	php "$dir/cli/joomla.php" extension:install --path="$BENCH_DIR/packages/$name.zip" -n > /dev/null
	# make sure it runs, regardless of the enabled state the installer leaves it in
	sql "bfperf_$name" -e "UPDATE jos_extensions SET enabled=1 WHERE type='plugin' AND folder='system' AND element='bfstop'"
}

build_package "$BASELINE_REF" baseline
build_package "$CURRENT_REF" current

for name in none baseline current; do
	install_joomla "$name"
done
install_plugin baseline
install_plugin current

# the first request after an installation is not representative (Joomla
# warms caches, bfstop's daily maintenance runs) - the benchmark does its own
# warm-up, nothing else to do here
cat > "$BENCH_DIR/sites.json" <<EOF
{
	"joomla": "$JOOMLA_VERSION",
	"db": {"host": "$DB_HOST", "user": "$DB_USER", "pass": "$DB_PASS"},
	"sites": {
		"none":     {"dir": "$BENCH_DIR/sites/none",     "db": "bfperf_none",     "port": 8101, "label": "no bfstop"},
		"baseline": {"dir": "$BENCH_DIR/sites/baseline", "db": "bfperf_baseline", "port": 8102, "label": "bfstop $BASELINE_REF", "package": "$BENCH_DIR/packages/baseline.zip"},
		"current":  {"dir": "$BENCH_DIR/sites/current",  "db": "bfperf_current",  "port": 8103, "label": "bfstop $CURRENT_REF ($(git -C "$repo" rev-parse --short "$CURRENT_REF"))", "package": "$BENCH_DIR/packages/current.zip"}
	}
}
EOF
echo "Done, see $BENCH_DIR/sites.json"
