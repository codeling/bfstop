#!/usr/bin/env bash
#
# Fetches a release file to FILE and checks its SHA-256; nothing that doesn't
# match is ever written to FILE. Used for the Joomla packages and the previous
# BFStop release the tests install.
#
# With DOWNLOAD_CACHE set (CI keeps that directory with actions/cache), a copy
# there is used instead of downloading it again, if its SHA-256 matches - the
# packages of a release never change, so a run needn't fetch the same tens of
# megabytes from GitHub for every job; a copy which doesn't match is replaced.
# A download is retried a few times on the errors that pass (timeouts, 429,
# 5xx), honouring Retry-After.
#
# Usage: fetch-verified.sh URL SHA256 FILE
set -euo pipefail

url="${1:?usage: fetch-verified.sh URL SHA256 FILE}"
expected="${2:?usage: fetch-verified.sh URL SHA256 FILE}"
file="${3:?usage: fetch-verified.sh URL SHA256 FILE}"
# the cache keeps a file under the name it has in the release (the last part
# of the URL), whatever FILE is called
name="$(basename "$url")"

sha256() {
	if command -v sha256sum > /dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

cached=""
if [ -n "${DOWNLOAD_CACHE:-}" ]; then
	mkdir -p "$DOWNLOAD_CACHE"
	cached="$DOWNLOAD_CACHE/$name"
	if [ -f "$cached" ]; then
		if [ "$(sha256 "$cached")" = "$expected" ]; then
			echo "Using $name from the download cache (SHA-256 verified)"
			cp "$cached" "$file"
			exit 0
		fi
		echo "Cached $name has another SHA-256, downloading it again"
		rm -f "$cached"
	fi
fi

echo "Downloading $url"
curl -fsSL --retry 3 --retry-delay 15 -o "$file.part" "$url"
actual="$(sha256 "$file.part")"
if [ "$actual" != "$expected" ]; then
	rm -f "$file.part"
	echo "SHA-256 of $name differs:" >&2
	echo "  expected $expected" >&2
	echo "  actual   $actual" >&2
	exit 1
fi
mv "$file.part" "$file"
if [ -n "$cached" ]; then
	cp "$file" "$cached"
fi
