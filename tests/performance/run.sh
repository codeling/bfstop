#!/usr/bin/env bash
#
# Sets up the Joomla sites (setup-sites.sh, skipped for sites which already
# exist) and runs the comparison (bench.php); all arguments go to bench.php.
# See README.md for the environment variables and the options.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$here/setup-sites.sh"
php "$here/bench.php" "$@"
