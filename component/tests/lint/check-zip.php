<?php
/*
 * @package BFStop for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 *
 * Checks that an installable extension zip (as built by deploy.sh zip)
 * contains everything its manifest references. Usage:
 *
 *   php tests/lint/check-zip.php <extension.zip> <manifest-name.xml>
 *
 * NOTE: this file is kept identical in the bfstop and com_bfstop repositories.
**/

if ($argc !== 3)
{
	fwrite(STDERR, "Usage: php {$argv[0]} <extension.zip> <manifest-name.xml>\n");
	exit(2);
}
[, $zipFile, $manifestName] = $argv;

$zip = new ZipArchive();
if ($zip->open($zipFile) !== true)
{
	fwrite(STDERR, "ERROR: cannot open $zipFile\n");
	exit(1);
}
$entries = array();
for ($i = 0; $i < $zip->numFiles; ++$i)
{
	$entries[] = rtrim($zip->getNameIndex($i), '/');
}

$manifest = $zip->getFromName($manifestName);
if ($manifest === false)
{
	fwrite(STDERR, "ERROR: manifest $manifestName is not at the top level of $zipFile\n");
	exit(1);
}
$xml = simplexml_load_string($manifest);

$expected = array();
$prefixed = function ($folder, $path) {
	return ltrim(($folder !== '' ? $folder.'/' : '').$path, '/');
};
foreach ($xml->xpath('//files') as $files)
{
	$folder = (string) $files['folder'];
	foreach ($files->children() as $child)
	{
		$expected[] = $prefixed($folder, (string) $child);
	}
}
foreach ($xml->xpath('//languages') as $languages)
{
	foreach ($languages->language as $language)
	{
		$expected[] = $prefixed((string) $languages['folder'], (string) $language);
	}
}
foreach ($xml->xpath('//scriptfile | //install/sql/file | //uninstall/sql/file | //update/schemas/schemapath') as $node)
{
	$expected[] = (string) $node;
}

$errors = 0;
foreach ($expected as $path)
{
	$found = false;
	foreach ($entries as $entry)
	{
		if ($entry === $path || str_starts_with($entry, $path.'/'))
		{
			$found = true;
			break;
		}
	}
	if (!$found)
	{
		echo (getenv('GITHUB_ACTIONS') === 'true' ? '::error::' : 'ERROR: ')."$zipFile is missing '$path' (referenced in $manifestName)\n";
		++$errors;
	}
}
echo count($expected)." manifest entries checked, $errors missing\n";
exit($errors > 0 ? 1 : 0);
