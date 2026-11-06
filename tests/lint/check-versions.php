<?php
/*
 * @package BFStop for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 *
 * Plugin, component and package are released together, with one version
 * number, which is written in several places. This checks that they agree:
 *
 *   - bfstop.xml (the plugin)
 *   - package/pkg_bfstop.xml (the package)
 *   - bfstop.xml of the component, if COM_BFSTOP_ROOT is set
 *   - the first entry of CHANGELOG ("2.0.0 (unreleased)" or "2.0.0 (2026-11-06)")
 *
 * A version is X.Y.Z, or X.Y.Z-alphaN, -betaN or -rcN for a test release
 * (which the update server never offers). The CHANGELOG entry of a test
 * release is that of the release it leads to: 2.1.0-rc1 has "2.1.0 (...)".
 *
 * Usage:
 *
 *   php tests/lint/check-versions.php                  they agree
 *   php tests/lint/check-versions.php --release=<tag>  ... and are <tag>; for a
 *                                                       release (not a test release)
 *                                                       the CHANGELOG entry has its date
 *   php tests/lint/check-versions.php --print-version  prints the plugin's version
 *   php tests/lint/check-versions.php --is-prerelease=<version>
 *                                                       exit status 0 if <version> is
 *                                                       a test release, 1 if not
**/

const VersionPattern = '/^(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)[1-9]\d*)?$/';

$root = dirname(__DIR__, 2);
$release = null;
foreach (array_slice($argv, 1) as $arg)
{
	if ($arg === '--print-version')
	{
		echo manifestVersion($root.'/bfstop.xml')."\n";
		exit(0);
	}
	if (str_starts_with($arg, '--is-prerelease='))
	{
		$version = substr($arg, strlen('--is-prerelease='));
		exit(preg_match(VersionPattern, $version, $m) && isset($m[2]) ? 0 : 1);
	}
	if (str_starts_with($arg, '--release='))
	{
		$release = substr($arg, strlen('--release='));
		continue;
	}
	fwrite(STDERR, "Usage: php {$argv[0]} [--release=<tag> | --print-version | --is-prerelease=<version>]\n");
	exit(2);
}

function manifestVersion($file)
{
	$xml = @simplexml_load_file($file);
	return $xml === false ? null : trim((string) $xml->version);
}

function fail($message)
{
	echo (getenv('GITHUB_ACTIONS') === 'true' ? '::error::' : 'ERROR: ').$message."\n";
}

$versions = array(
	'bfstop.xml' => manifestVersion($root.'/bfstop.xml'),
	'package/pkg_bfstop.xml' => manifestVersion($root.'/package/pkg_bfstop.xml'),
);
$componentRoot = getenv('COM_BFSTOP_ROOT');
if ($componentRoot)
{
	$versions['com_bfstop bfstop.xml'] = manifestVersion($componentRoot.'/bfstop.xml');
}

$changelogVersion = null;
$changelogDate = null;
foreach (file($root.'/CHANGELOG', FILE_IGNORE_NEW_LINES) as $line)
{
	if (trim($line) === '')
	{
		continue;
	}
	// the first line which isn't empty is the newest entry
	if (preg_match('/^(\S+) \((.+)\)$/', $line, $match))
	{
		$changelogVersion = $match[1];
		$changelogDate = $match[2];
	}
	break;
}

$errors = 0;
$expected = $release ?? $versions['bfstop.xml'];
if ($expected === null || !preg_match(VersionPattern, $expected, $match))
{
	fail(($release !== null ? "the tag" : "bfstop.xml")." has no valid version: '$expected' ".
		"(X.Y.Z, or X.Y.Z-alphaN, -betaN, -rcN for a test release)");
	exit(1);
}
$base = $match[1];
$prerelease = isset($match[2]);

foreach ($versions as $where => $version)
{
	if ($version === null || $version === '')
	{
		fail("no version found in $where");
		++$errors;
	}
	elseif ($version !== $expected)
	{
		fail("$where has version $version, expected $expected".($release !== null ? ' (the tag)' : ' (as in bfstop.xml)'));
		++$errors;
	}
}
if ($changelogVersion !== $base)
{
	fail("the first CHANGELOG entry has to be '$base (...)'".($prerelease ? " (that of the release $expected leads to)" : '').
		", it is ".($changelogVersion === null ? 'missing' : "'$changelogVersion'"));
	++$errors;
}
elseif ($release !== null && !$prerelease &&
	(!preg_match('/^\d{4}-\d{2}-\d{2}$/', $changelogDate) || strtotime($changelogDate) === false))
{
	fail("the CHANGELOG entry of $release has no release date: '$changelogDate' (write it as YYYY-MM-DD)");
	++$errors;
}

echo (count($versions) + 1)." versions checked".($release !== null ? " against ".($prerelease ? 'test release ' : 'release ').$release : '').
	", $errors problem(s)\n";
exit($errors > 0 ? 1 : 0);
