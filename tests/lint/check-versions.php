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
 *   - package/pkg_bfstop.xml and package/update.xml (the package)
 *   - the first entry of CHANGELOG ("2.0.0 (unreleased)" or "2.0.0 (2026-11-06)")
 *   - bfstop.xml of the component, if COM_BFSTOP_ROOT is set
 *
 * Usage:
 *
 *   php tests/lint/check-versions.php                    all agree
 *   php tests/lint/check-versions.php --release=<tag>    ... are <tag>, and the
 *                                                         CHANGELOG entry has a date
 *   php tests/lint/check-versions.php --print-version    prints the plugin's version
**/

$root = dirname(__DIR__, 2);
$release = null;
foreach (array_slice($argv, 1) as $arg)
{
	if ($arg === '--print-version')
	{
		echo manifestVersion($root.'/bfstop.xml')."\n";
		exit(0);
	}
	if (str_starts_with($arg, '--release='))
	{
		$release = substr($arg, strlen('--release='));
		continue;
	}
	fwrite(STDERR, "Usage: php {$argv[0]} [--release=<tag> | --print-version]\n");
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
$update = @simplexml_load_file($root.'/package/update.xml');
$versions['package/update.xml'] = $update === false ? null : (string) $update->extension['version'];

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
		$versions['CHANGELOG'] = $match[1];
		$changelogDate = $match[2];
	}
	else
	{
		$versions['CHANGELOG'] = null;
	}
	break;
}

$componentRoot = getenv('COM_BFSTOP_ROOT');
if ($componentRoot)
{
	$versions['com_bfstop bfstop.xml'] = manifestVersion($componentRoot.'/bfstop.xml');
}

$errors = 0;
$expected = $release ?? $versions['bfstop.xml'];
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
if ($release !== null && $changelogDate !== null &&
	(!preg_match('/^\d{4}-\d{2}-\d{2}$/', $changelogDate) || strtotime($changelogDate) === false))
{
	fail("the CHANGELOG entry of $release has no release date: '$changelogDate' (write it as YYYY-MM-DD)");
	++$errors;
}

echo count($versions)." versions checked".($release !== null ? " against release $release" : '').", $errors problem(s)\n";
exit($errors > 0 ? 1 : 0);
