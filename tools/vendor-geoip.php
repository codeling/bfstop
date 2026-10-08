<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Copies the MaxMind DB reader (maxmind-db/reader, installed by composer from
// composer.lock) into src/Helper/Geo, the way the plugin ships it: Joomla
// extensions have no composer at install time, so the code is vendored into the
// package. The only changes made to the upstream files are the namespace, the
// licence header and the _JEXEC guard - so the result is reproducible, and
// `--check` can tell whether the copy in src/Helper/Geo is the version in
// composer.lock, unmodified.
//
//   composer install
//   php tools/vendor-geoip.php           (re)writes src/Helper/Geo
//   php tools/vendor-geoip.php --check   exits 1 if src/Helper/Geo differs
//
// Updating the reader: `composer update maxmind-db/reader`, then
// `composer vendor-geoip`, then review the diff and run the tests.
//
// Optional: --vendor-dir=DIR to take the sources from another vendor directory.

if (PHP_SAPI !== 'cli')
{
	exit(1);
}

const TargetNamespace = 'Codeling\\Plugin\\System\\Bfstop\\Helper\\Geo';

$root = dirname(__DIR__);
$check = false;
$vendorDir = $root.'/vendor';
foreach (array_slice($argv, 1) as $arg)
{
	if ($arg === '--check')
	{
		$check = true;
	}
	elseif (strpos($arg, '--vendor-dir=') === 0)
	{
		$vendorDir = rtrim(substr($arg, strlen('--vendor-dir=')), '/');
	}
	else
	{
		fwrite(STDERR, "Unknown argument: $arg\n");
		exit(2);
	}
}

function fail($message)
{
	fwrite(STDERR, $message."\n");
	exit(2);
}

function installedVersion($vendorDir)
{
	$file = $vendorDir.'/composer/installed.json';
	if (!is_file($file))
	{
		fail("$file not found - run 'composer install' first.");
	}
	$installed = json_decode(file_get_contents($file), true);
	foreach ($installed['packages'] ?? $installed as $package)
	{
		if (($package['name'] ?? '') === 'maxmind-db/reader')
		{
			return ltrim($package['version'], 'v');
		}
	}
	fail('maxmind-db/reader is not installed - run composer install.');
}

function lockedVersion($root)
{
	$lock = json_decode(file_get_contents($root.'/composer.lock'), true);
	foreach ($lock['packages'] as $package)
	{
		if ($package['name'] === 'maxmind-db/reader')
		{
			return ltrim($package['version'], 'v');
		}
	}
	fail('maxmind-db/reader is not in composer.lock.');
}

$version = installedVersion($vendorDir);
if ($vendorDir === $root.'/vendor' && $version !== lockedVersion($root))
{
	fail("vendor/ holds maxmind-db/reader $version, composer.lock says ".lockedVersion($root).
		" - run 'composer install'.");
}
$source = $vendorDir.'/maxmind-db/reader/src/MaxMind/Db';
$target = $root.'/src/Helper/Geo';

$mainHeader = <<<TXT
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 *
 * This file is vendored from maxmind-db/reader $version
 * (https://github.com/maxmind/MaxMind-DB-Reader-php), used here as a small,
 * dependency-free (core PHP only) reader for MaxMind .mmdb GeoIP databases,
 * so BFStop can look up an IP's country/city locally instead of relying on a
 * third-party web API (see issues #76 and #169). Only the namespace, this
 * header and the _JEXEC guard have been changed; the decoding logic is
 * unmodified. Do not edit by hand: tools/vendor-geoip.php regenerates it from
 * composer.lock (see README, "GeoIP reader").
 *
 * Original work Copyright (C) MaxMind, Inc., licensed under the
 * Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
**/
TXT;
$shortHeader = <<<TXT
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 *
 * Vendored from maxmind-db/reader $version (see Geo/Reader.php for details).
 * Original work Copyright (C) MaxMind, Inc., licensed under the
 * Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
**/
TXT;

function transform($code, $header, $relative)
{
	$code = str_replace("\r\n", "\n", $code);
	$count = 0;
	// the namespace, and the guard directly after its declaration
	$code = preg_replace('/^namespace MaxMind\\\\Db(\\\\[A-Za-z]+)?;$/m',
		"namespace ".TargetNamespace."\$1;\n\ndefined('_JEXEC') or die;", $code, 1, $count);
	if ($count !== 1)
	{
		fail("$relative: no namespace declaration found - has the upstream layout changed?");
	}
	$code = preg_replace('/^use MaxMind\\\\Db\\\\/m', 'use '.TargetNamespace.'\\', $code);
	if (strpos($code, 'MaxMind\\Db\\') !== false && preg_match('/^(use|namespace) MaxMind/m', $code))
	{
		fail("$relative: unrewritten MaxMind namespace left.");
	}
	if (strncmp($code, "<?php\n", 6) !== 0)
	{
		fail("$relative: does not start with '<?php'.");
	}
	return "<?php\n".$header."\n".substr($code, 6);
}

$generated = array();
$files = array('Reader.php' => $mainHeader);
foreach (glob($source.'/Reader/*.php') as $file)
{
	$files['Reader/'.basename($file)] = $shortHeader;
}
if (!is_file($source.'/Reader.php') || count($files) < 2)
{
	fail("No reader sources found in $source.");
}
foreach ($files as $relative => $header)
{
	$generated[$relative] = transform(file_get_contents($source.'/'.$relative), $header, $relative);
}
$generated['LICENSE'] = file_get_contents($vendorDir.'/maxmind-db/reader/LICENSE');

$differences = array();
foreach ($generated as $relative => $content)
{
	$path = $target.'/'.$relative;
	if (!is_file($path) || file_get_contents($path) !== $content)
	{
		$differences[] = $relative;
		if (!$check)
		{
			if (!is_dir(dirname($path)))
			{
				mkdir(dirname($path), 0777, true);
			}
			file_put_contents($path, $content);
		}
	}
}
// files which upstream no longer has
$existing = array_merge(glob($target.'/*.php'), glob($target.'/Reader/*.php'));
foreach ($existing as $path)
{
	$relative = substr($path, strlen($target) + 1);
	if (!isset($generated[$relative]))
	{
		$differences[] = "$relative (not in maxmind-db/reader $version)";
		if (!$check)
		{
			unlink($path);
		}
	}
}

if ($check)
{
	if ($differences)
	{
		fwrite(STDERR, "src/Helper/Geo is not maxmind-db/reader $version as locked in composer.lock:\n  ".
			implode("\n  ", $differences)."\nRun 'composer vendor-geoip' and commit the result.\n");
		exit(1);
	}
	echo "src/Helper/Geo is maxmind-db/reader $version, as locked in composer.lock.\n";
	exit(0);
}
echo $differences
	? "Updated src/Helper/Geo to maxmind-db/reader $version: ".implode(', ', $differences)."\n"
	: "src/Helper/Geo already is maxmind-db/reader $version.\n";
