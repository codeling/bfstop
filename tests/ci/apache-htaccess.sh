#!/usr/bin/env bash
#
# Checks the block section the plugin writes into a .htaccess file against a
# real Apache 2.4 (apache2 and apache2-utils installed, as on Ubuntu): it must
# turn away the blocked addresses, and nothing else - in particular it must not
# open up what the directory's other access controls keep out. Apache combines
# the authorization directives at the top level of a configuration section with
# an implicit <RequireAny>, so a "Require all granted" in the section (as
# versions up to 2.0.0 wrote) let everybody who isn't blocked past HTTP
# authentication and "Require all denied".
#
# The section is written by HtaccessHelper itself (tests/Integration/fixtures/
# deny_ip.php), into
#   protected/ - HTTP Basic authentication in the same .htaccess
#   denied/    - closed by the server configuration
#   open/      - nothing else
# and each is requested from 127.0.0.1, with that address blocked and not.
#
# Usage: tests/ci/apache-htaccess.sh
set -euo pipefail

plugin_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
modules="${APACHE_MODULES:-/usr/lib/apache2/modules}"
port="${APACHE_PORT:-18080}"
failures=0

cleanup() {
	apache2 -f "$work/httpd.conf" -k stop > /dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

htpasswd -bc "$work/htpasswd" staff secret > /dev/null 2>&1
cat > "$work/httpd.conf" <<CONF
ServerRoot "$work"
ServerName localhost
PidFile "$work/httpd.pid"
Listen 127.0.0.1:$port
LoadModule mpm_event_module $modules/mod_mpm_event.so
LoadModule authz_core_module $modules/mod_authz_core.so
LoadModule authz_host_module $modules/mod_authz_host.so
LoadModule authz_user_module $modules/mod_authz_user.so
LoadModule authn_core_module $modules/mod_authn_core.so
LoadModule authn_file_module $modules/mod_authn_file.so
LoadModule auth_basic_module $modules/mod_auth_basic.so
LoadModule dir_module $modules/mod_dir.so
ErrorLog "$work/error.log"
DocumentRoot "$work/www"
DirectoryIndex index.html
<Directory "$work/www">
	AllowOverride All
	Require all granted
</Directory>
<Directory "$work/www/denied">
	Require all denied
</Directory>
CONF

# $1: the address to block besides a few others ("" for none)
setup() {
	rm -rf "$work/www"
	for dir in protected denied open; do
		mkdir -p "$work/www/$dir"
		echo "$dir" > "$work/www/$dir/index.html"
	done
	printf 'AuthType Basic\nAuthName "Staff only"\nAuthUserFile "%s/htpasswd"\nRequire valid-user\n' "$work" \
		> "$work/www/protected/.htaccess"
	# more addresses than fit into one condition, and an IPv6 network
	for dir in protected denied open; do
		for i in $(seq 1 60); do
			php "$plugin_root/tests/Integration/fixtures/deny_ip.php" "$work/www/$dir" "198.51.100.$i"
		done
		php "$plugin_root/tests/Integration/fixtures/deny_ip.php" "$work/www/$dir" "2001:db8::/32"
		if [ -n "$1" ]; then
			php "$plugin_root/tests/Integration/fixtures/deny_ip.php" "$work/www/$dir" "$1"
		fi
	done
	apache2 -f "$work/httpd.conf" -k stop > /dev/null 2>&1 || true
	sleep 1
	apache2 -f "$work/httpd.conf" -k start
	sleep 1
}

# $1: description, $2: expected status, $3...: curl arguments
expect() {
	local what="$1" expected="$2" actual
	shift 2
	actual="$(curl -s -o /dev/null -w '%{http_code}' "$@")"
	if [ "$actual" = "$expected" ]; then
		echo "ok   $what: $actual"
	else
		echo "FAIL $what: $actual, expected $expected"
		failures=$((failures + 1))
	fi
}

url="http://127.0.0.1:$port"

setup ""
expect "not blocked, protected/ without credentials" 401 "$url/protected/"
expect "not blocked, protected/ with credentials" 200 -u staff:secret "$url/protected/"
expect "not blocked, denied/" 403 "$url/denied/"
expect "not blocked, open/" 200 "$url/open/"

setup "127.0.0.1"
expect "blocked, protected/ without credentials" 403 "$url/protected/"
expect "blocked, protected/ with credentials" 403 -u staff:secret "$url/protected/"
expect "blocked, denied/" 403 "$url/denied/"
expect "blocked, open/" 403 "$url/open/"

if grep -q 'AH0[0-9]*: .*\(Syntax\|syntax error\|Invalid\)' "$work/error.log"; then
	echo "FAIL the error log reports configuration errors:"
	cat "$work/error.log"
	failures=$((failures + 1))
fi
if [ "$failures" -gt 0 ]; then
	echo "Section written:"
	sed -n '/# BEGIN BFStop Blocks/,/# END BFStop Blocks/p' "$work/www/open/.htaccess" | head -20
	exit 1
fi
