#!/usr/bin/env bash
#
# Runs phpstan (configuration: phpstan.neon) against an unpacked Joomla!, which
# gives it the types of Joomla's classes (there is no stubs package; the real
# libraries/ directory is what the code runs against).
#
# Without JOOMLA_ROOT, the newest Joomla version of the test matrix
# (tests/ci/matrix.json) is downloaded and verified by download-joomla.sh into a
# temporary directory. Needs `composer install` (phpstan is a dev dependency).
#
# Usage: phpstan.sh [phpstan arguments, e.g. --generate-baseline phpstan-baseline.neon]
#
# Environment:
#   JOOMLA_ROOT     an unpacked Joomla! to analyse against, instead of downloading one
#   DOWNLOAD_CACHE  optional, see download-joomla.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

if [ ! -x vendor/bin/phpstan ]; then
	echo "vendor/bin/phpstan not found: run 'composer install' first" >&2
	exit 1
fi

if [ -z "${JOOMLA_ROOT:-}" ]; then
	version="$(jq -r '[.include[].joomla] | unique | .[]' tests/ci/matrix.json | sort -V | tail -n 1)"
	JOOMLA_ROOT="$(mktemp -d)"
	trap 'rm -rf "$JOOMLA_ROOT"' EXIT
	"$root/tests/ci/download-joomla.sh" "$version" "$JOOMLA_ROOT"
fi
export JOOMLA_ROOT

vendor/bin/phpstan analyse --no-progress --memory-limit=1G "$@"
