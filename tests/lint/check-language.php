<?php
/*
 * @package BFStop for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 *
 * Sanity checks for Joomla! language files. Usage:
 *
 *   php tests/lint/check-language.php <manifest.xml> [<KEY_PREFIX>...]
 *
 * Errors (exit code 1):
 *  - an .ini file which PHP/Joomla cannot parse
 *  - a key without one of the given prefixes (only if prefixes are given)
 *  - a file whose language tag does not match the folder it is in
 *  - a language file referenced in the manifest which does not exist
 * Warnings (reported, but exit code 0):
 *  - keys present in en-GB but missing in a translation, or vice versa
 *
 * NOTE: this file is kept identical in the bfstop and com_bfstop repositories.
**/

if ($argc < 2)
{
	fwrite(STDERR, "Usage: php {$argv[0]} <manifest.xml> [<KEY_PREFIX>...]\n");
	exit(2);
}

$manifest = $argv[1];
$prefixes = array_slice($argv, 2);
$root = dirname(realpath($manifest));
$errors = array();
$warnings = array();

// 1. every language file referenced in the manifest must exist
$xml = simplexml_load_file($manifest);
if ($xml === false)
{
	fwrite(STDERR, "ERROR: cannot parse manifest $manifest\n");
	exit(1);
}
foreach ($xml->xpath('//languages') as $languages)
{
	$folder = (string) $languages['folder'];
	foreach ($languages->language as $language)
	{
		$path = $root.'/'.($folder !== '' ? $folder.'/' : '').(string) $language;
		if (!is_file($path))
		{
			$errors[] = "manifest references missing language file $path";
		}
	}
}

// 2. parse all .ini files, grouped by "<dir-of-tag-folders>|<basename without tag>"
$groups = array();
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach ($it as $file)
{
	$path = $file->getPathname();
	if ($file->getExtension() !== 'ini' || preg_match('#/(vendor|node_modules|\.git)/#', $path))
	{
		continue;
	}
	$rel = substr($path, strlen($root) + 1);
	if (!preg_match('/^([a-z]{2,3}-[A-Z]{2})\.(.+)$/', $file->getFilename(), $m))
	{
		$errors[] = "$rel: file name does not start with a language tag";
		continue;
	}
	[, $tag, $base] = $m;
	if (basename(dirname($path)) !== $tag)
	{
		$errors[] = "$rel: file for language $tag is not located in a $tag/ folder (Joomla will never load it)";
		continue;
	}

	// Joomla parses language files like this (see LanguageHelper::parseIniFile)
	$contents = str_replace('"_QQ_"', '\\"', file_get_contents($path));
	$strings = @parse_ini_string($contents, false, INI_SCANNER_RAW);
	if ($strings === false)
	{
		$err = error_get_last();
		$errors[] = "$rel: cannot be parsed: ".($err['message'] ?? 'unknown error');
		continue;
	}
	foreach (array_keys($strings) as $key)
	{
		$ok = count($prefixes) === 0;
		foreach ($prefixes as $prefix)
		{
			if (str_starts_with($key, $prefix))
			{
				$ok = true;
				break;
			}
		}
		if (!$ok)
		{
			$errors[] = "$rel: key '$key' does not start with ".implode(' or ', $prefixes);
		}
	}
	$groups[dirname($path, 2).'|'.$base][$tag] = array('rel' => $rel, 'keys' => array_keys($strings));
}

// 3. compare translations against en-GB
foreach ($groups as $group => $langs)
{
	if (!isset($langs['en-GB']))
	{
		$warnings[] = "no en-GB reference file for group $group";
		continue;
	}
	$reference = $langs['en-GB']['keys'];
	foreach ($langs as $tag => $info)
	{
		if ($tag === 'en-GB')
		{
			continue;
		}
		$missing = array_diff($reference, $info['keys']);
		$extra = array_diff($info['keys'], $reference);
		if ($missing)
		{
			$warnings[] = $info['rel'].': '.count($missing).' key(s) missing (en-GB fallback is used): '.implode(', ', $missing);
		}
		if ($extra)
		{
			$warnings[] = $info['rel'].': '.count($extra).' key(s) not in en-GB (obsolete?): '.implode(', ', $extra);
		}
	}
}

$gha = getenv('GITHUB_ACTIONS') === 'true';
foreach ($warnings as $w)
{
	echo ($gha ? '::warning::' : 'WARNING: ').$w."\n";
}
foreach ($errors as $e)
{
	echo ($gha ? '::error::' : 'ERROR: ').$e."\n";
}
echo count($errors).' error(s), '.count($warnings)." warning(s)\n";
exit(count($errors) > 0 ? 1 : 0);
