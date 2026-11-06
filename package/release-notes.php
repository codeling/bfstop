<?php
/*
 * @package BFStop for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 *
 * Writes the notes of a GitHub release (Markdown) to stdout: what the release
 * needs (from package/script.php), its CHANGELOG entry, and the SHA-256 sums
 * from the build directory. A test release (X.Y.Z-alphaN, -betaN, -rcN) gets
 * the entry of the release it leads to, and says that it is one.
 *
 * Usage: php package/release-notes.php <version> <build directory>
**/

if ($argc !== 3)
{
	fwrite(STDERR, "Usage: php {$argv[0]} <version> <build directory>\n");
	exit(2);
}
[, $version, $buildDir] = $argv;
$root = dirname(__DIR__);

if (!preg_match('/^(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)[1-9]\d*)?$/', $version, $match))
{
	fwrite(STDERR, "Not a version: $version\n");
	exit(1);
}
$base = $match[1];
$prerelease = isset($match[2]);

// the CHANGELOG entry: from its "X.Y.Z (date)" line to the next one
$entry = array();
$inEntry = false;
foreach (file($root.'/CHANGELOG', FILE_IGNORE_NEW_LINES) as $line)
{
	if (preg_match('/^(\S+) \((.+)\)$/', $line, $header))
	{
		if ($inEntry)
		{
			break;
		}
		$inEntry = ($header[1] === $base);
		continue;
	}
	if ($inEntry)
	{
		$entry[] = $line;
	}
}
if (count($entry) === 0)
{
	fwrite(STDERR, "No CHANGELOG entry for $base\n");
	exit(1);
}

$script = (string) file_get_contents($root.'/package/script.php');
$joomla = preg_match('/\$minimumJoomla = \'([0-9.]+)\'/', $script, $m) ? $m[1] : null;
$php = preg_match('/\$minimumPhp = \'([0-9.]+)\'/', $script, $m) ? $m[1] : null;

$sums = glob(rtrim($buildDir, '/').'/SHA256SUMS-'.$version);

if ($prerelease)
{
	echo "> [!WARNING]\n".
		"> **Test release** of BFStop $base, for trying it out before the release - preferably on a test site.\n".
		"> It is not offered through Joomla's update. A site which installs it is offered $base there once that is released; later test releases have to be installed the same way as this one.\n\n";
}
echo "Install **pkg_bfstop-$version.zip** (plugin and component) through Joomla's extension installer";
if ($joomla !== null && $php !== null)
{
	echo "; it needs Joomla! ".preg_replace('/\.0(\.0)?$/', '', $joomla)." or later and PHP ".preg_replace('/\.0$/', '', $php)." or later";
}
echo ".\n\n";
echo "## Changes".($prerelease ? " in $base" : '')."\n\n```text\n".rtrim(implode("\n", $entry))."\n```\n";
if (count($sums) === 1)
{
	echo "\n## SHA-256\n\n```text\n".rtrim((string) file_get_contents($sums[0]))."\n```\n";
}
