<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Usage: php tests/lint/check-joomla-checksums.php
//
// The integration tests only install a Joomla! package whose SHA-256 is in
// tests/ci/joomla-checksums.sha256 (see tests/ci/download-joomla.sh). This
// checks that the file is well-formed and lists every Joomla! version of the
// matrix of the integration tests (tests/ci/matrix.json, read by
// .github/workflows/ci.yml; also checked for being well-formed), so that
// raising a version without its checksum fails here, not in half a dozen
// integration jobs.
//
// Exits with status 1 on an error.

$root = dirname(__DIR__, 2);
$errors = 0;

$listed = array();
foreach (file($root.'/tests/ci/joomla-checksums.sha256') as $number => $line)
{
	$line = rtrim($line);
	if ($line === '' || $line[0] === '#')
	{
		continue;
	}
	if (!preg_match('/^([0-9a-f]{64})  Joomla_(\d+\.\d+\.\d+)-Stable-Full_Package\.tar\.gz$/', $line, $m))
	{
		echo "ERROR: tests/ci/joomla-checksums.sha256:".($number + 1).": not '<sha256>  Joomla_<version>-Stable-Full_Package.tar.gz'\n";
		++$errors;
		continue;
	}
	if (isset($listed[$m[2]]))
	{
		echo "ERROR: tests/ci/joomla-checksums.sha256:".($number + 1).": version {$m[2]} is listed twice\n";
		++$errors;
	}
	$listed[$m[2]] = true;
}

$used = array();
$matrix = json_decode(file_get_contents($root.'/tests/ci/matrix.json'), true);
if (!is_array($matrix) || !is_array($matrix['include'] ?? null) || count($matrix['include']) === 0)
{
	echo "ERROR: tests/ci/matrix.json is not JSON with a non-empty \"include\" list\n";
	++$errors;
	$matrix = array('include' => array());
}
foreach ($matrix['include'] as $number => $entry)
{
	$where = "tests/ci/matrix.json: entry ".($number + 1);
	foreach (array('joomla', 'php', 'db') as $key)
	{
		if (!is_array($entry) || !isset($entry[$key]) || !is_string($entry[$key]) || $entry[$key] === '')
		{
			echo "ERROR: $where has no \"$key\" (string)\n";
			++$errors;
			continue 2;
		}
	}
	$version = $entry['joomla'];
	if (!preg_match('/^\d+\.\d+\.\d+$/', $version))
	{
		echo "ERROR: $where: \"$version\" is not a Joomla version like 5.4.8\n";
		++$errors;
		continue;
	}
	$used[$version] = true;
	if (!isset($listed[$version]))
	{
		echo "ERROR: Joomla $version is in tests/ci/matrix.json, but has no checksum in tests/ci/joomla-checksums.sha256\n";
		++$errors;
	}
}
if (count($used) === 0)
{
	echo "ERROR: no Joomla version found in tests/ci/matrix.json\n";
	++$errors;
}
foreach (array_diff_key($listed, $used) as $version => $unused)
{
	echo "NOTE: Joomla $version has a checksum, but is not in tests/ci/matrix.json\n";
}
echo count($used)." version(s) of the matrix checked against ".count($listed)." checksum(s), $errors error(s)\n";
exit($errors > 0 ? 1 : 0);
