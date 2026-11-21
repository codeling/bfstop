<?php
/*
 * @package BFStop for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 *
 * Writes the files of the update server, https://bfstop.de
 * (GitHub Pages, .github/workflows/pages.yml): the update sites of the
 * installed extensions ask for
 *
 *   update.xml      the collection ("which extensions are there"), pointing at
 *   update-pkg.xml  the updates of the package, one per version line
 *
 * Only *published* GitHub releases that are not marked as pre-release count:
 * a draft is not published yet, and a test release (X.Y.Z-rcN, ...) is for
 * the testers who install it by hand - sites must never be offered one.
 *
 * Each major version is a "line" with the Joomla! versions it runs on (see
 * updateServerLines()); the newest release of each line is offered to the
 * sites of its Joomla! versions, so a Joomla! 4 site stays with 1.x and a
 * site on Joomla! 5.0-5.3 (which the 2.x installer refuses) is not offered
 * 2.x. A stable release of a major version *newer* than the lines is an
 * error: what to offer to which site has to be decided first. Releases of
 * older major versions than the first line (0.9.x) are not offered.
 *
 * Usage: php package/update-server.php RELEASES.json OUTPUT_DIRECTORY
 *   RELEASES.json is the answer of the GitHub API for
 *   /repos/codeling/bfstop/releases (a list, or - gh api --paginate --slurp -
 *   a list of the pages).
**/

const UpdateServerPackageAsset = 'pkg_bfstop-%s.zip';
const UpdateServerDetailsUrl = 'https://bfstop.de/update-pkg.xml';
const UpdateServerPackageName = 'Brute Force Stop Package';

/**
 * The version lines, by major version. The targetplatform is a regular
 * expression which Joomla! matches against the *start* of its own version
 * (7.0.0 doesn't match '(5\.[4-9]|6)\..*', which is as it should be: BFStop
 * 2 has not been tested on it). php_minimum is the PHP version the line
 * needs (null: not stated).
 *
 * @return array[]
 */
function updateServerLines()
{
	return array(
		// 1.5 (Joomla 4, 5; the sites which can't, or haven't yet, got to the
		// requirements of 2.x)
		1 => array('targetplatform' => '(4|5\.[0-3])\..*', 'php_minimum' => null),
		// 2.x: package/script.php refuses anything older than Joomla! 5.4
		// and PHP 8.2
		2 => array('targetplatform' => '(5\.[4-9]|6)\..*', 'php_minimum' => '8.2'),
	);
}

/**
 * @param array $releases the GitHub API's releases, or a list of lists of
 *        them (one per page, as `gh api --paginate --slurp` writes them)
 * @return array[] the releases, flat
 */
function updateServerFlatten(array $releases)
{
	$flat = array();
	foreach ($releases as $release)
	{
		if (is_array($release) && array_is_list($release))
		{
			$flat = array_merge($flat, $release);
		}
		else
		{
			$flat[] = $release;
		}
	}
	return $flat;
}

/**
 * @param array $releases GitHub releases
 * @return array[] the releases which sites are offered, newest first, each
 *         with its 'version'
 */
function updateServerStableReleases(array $releases)
{
	$stable = array();
	foreach (updateServerFlatten($releases) as $release)
	{
		if (!is_array($release) || !empty($release['draft']) || !empty($release['prerelease']))
		{
			continue;
		}
		$tag = (string) ($release['tag_name'] ?? '');
		if (!preg_match('/^\d+\.\d+\.\d+$/', $tag))
		{
			// a release is X.Y.Z: whatever else is tagged (and published
			// without the pre-release mark) is not meant for the update server
			fwrite(STDERR, "Ignoring release '$tag': not a version X.Y.Z\n");
			continue;
		}
		if ((int) explode('.', $tag)[0] < min(array_keys(updateServerLines())))
		{
			// the releases from before the first line (0.9.x) are history: the
			// sites which have them are not offered anything
			fwrite(STDERR, "Not offering release $tag: older than the first version line\n");
			continue;
		}
		$release['version'] = $tag;
		$stable[] = $release;
	}
	usort($stable, fn ($a, $b) => version_compare($b['version'], $a['version']));
	return $stable;
}

/**
 * @param array[] $stable updateServerStableReleases()
 * @return array[] the newest release of each line (the keys are the majors)
 * @throws RuntimeException for a release of a major version without a line
 */
function updateServerNewestPerLine(array $stable)
{
	$lines = updateServerLines();
	$newest = array();
	foreach ($stable as $release)
	{
		$major = (int) explode('.', $release['version'])[0];
		if (!isset($lines[$major]))
		{
			throw new RuntimeException("Release {$release['version']} has no version line in updateServerLines():"
				." decide which Joomla! versions it is offered to first");
		}
		if (!isset($newest[$major])) // newest first
		{
			$newest[$major] = $release;
		}
	}
	krsort($newest);
	return $newest;
}

/**
 * @param array $release a GitHub release
 * @param callable $fetch url => the file's content, for an asset without a digest
 * @return array the package asset of the release, with its 'sha256'
 * @throws RuntimeException if the release has no package, or it can't be hashed
 */
function updateServerPackage(array $release, callable $fetch)
{
	$name = sprintf(UpdateServerPackageAsset, $release['version']);
	foreach ($release['assets'] ?? array() as $asset)
	{
		if (($asset['name'] ?? '') !== $name)
		{
			continue;
		}
		$url = (string) ($asset['browser_download_url'] ?? '');
		if (strpos($url, 'https://') !== 0)
		{
			throw new RuntimeException("Asset $name of {$release['version']} has no https download URL");
		}
		$sha256 = null;
		if (preg_match('/^sha256:([0-9a-f]{64})$/', (string) ($asset['digest'] ?? ''), $m))
		{
			$sha256 = $m[1];
		}
		else
		{
			// releases from before GitHub kept digests of the assets
			$content = $fetch($url);
			if (!is_string($content) || $content === '')
			{
				throw new RuntimeException("Could not download $url to get its SHA-256");
			}
			$sha256 = hash('sha256', $content);
		}
		return array('url' => $url, 'sha256' => $sha256);
	}
	throw new RuntimeException("Release {$release['version']} has no asset $name");
}

/**
 * @param array[] $newest updateServerNewestPerLine()
 * @param callable $fetch see updateServerPackage()
 * @return string update-pkg.xml
 */
function updateServerDetailsXml(array $newest, callable $fetch)
{
	$lines = updateServerLines();
	$doc = new DOMDocument('1.0', 'UTF-8');
	$doc->formatOutput = true;
	$updates = $doc->appendChild($doc->createElement('updates'));
	foreach ($newest as $major => $release)
	{
		$package = updateServerPackage($release, $fetch);
		$update = $updates->appendChild($doc->createElement('update'));
		$add = function ($name, $value, $attributes = array()) use ($doc, $update)
		{
			$element = $update->appendChild($doc->createElement($name));
			$element->appendChild($doc->createTextNode($value));
			foreach ($attributes as $key => $attribute)
			{
				$element->setAttribute($key, $attribute);
			}
			return $element;
		};
		$add('name', UpdateServerPackageName);
		$add('description', UpdateServerPackageName.' '.$release['version']);
		$add('element', 'pkg_bfstop');
		$add('type', 'package');
		$add('version', $release['version']);
		$add('client', 'site');
		$add('infourl', (string) ($release['html_url'] ?? ''), array('title' => 'BFStop '.$release['version']));
		$downloads = $update->appendChild($doc->createElement('downloads'));
		$download = $downloads->appendChild($doc->createElement('downloadurl'));
		$download->setAttribute('type', 'full');
		$download->setAttribute('format', 'zip');
		$download->appendChild($doc->createTextNode($package['url']));
		$add('sha256', $package['sha256']);
		$tags = $update->appendChild($doc->createElement('tags'));
		$tags->appendChild($doc->createElement('tag', 'stable'));
		$add('maintainer', 'Bernhard Froehler');
		$add('maintainerurl', 'https://github.com/codeling/bfstop');
		$platform = $update->appendChild($doc->createElement('targetplatform'));
		$platform->setAttribute('name', 'joomla');
		$platform->setAttribute('version', $lines[$major]['targetplatform']);
		if ($lines[$major]['php_minimum'] !== null)
		{
			$add('php_minimum', $lines[$major]['php_minimum']);
		}
	}
	return $doc->saveXML();
}

/**
 * @param string $version the newest release
 * @return string update.xml
 */
function updateServerCollectionXml($version)
{
	$doc = new DOMDocument('1.0', 'UTF-8');
	$doc->formatOutput = true;
	$set = $doc->appendChild($doc->createElement('extensionset'));
	$set->setAttribute('name', UpdateServerPackageName);
	$set->setAttribute('description', UpdateServerPackageName);
	$extension = $set->appendChild($doc->createElement('extension'));
	$extension->setAttribute('name', UpdateServerPackageName);
	$extension->setAttribute('element', 'pkg_bfstop');
	$extension->setAttribute('type', 'package');
	$extension->setAttribute('version', $version);
	$extension->setAttribute('detailsurl', UpdateServerDetailsUrl);
	return $doc->saveXML();
}

/**
 * @param array $releases GitHub releases
 * @param callable $fetch see updateServerPackage()
 * @return string[] the content of the files of the update server, by name
 * @throws RuntimeException if there is nothing to offer, or what there is can't be
 */
function updateServerFiles(array $releases, callable $fetch)
{
	$stable = updateServerStableReleases($releases);
	if (count($stable) === 0)
	{
		throw new RuntimeException('There is no published release (which is not a pre-release): nothing to offer');
	}
	$newest = updateServerNewestPerLine($stable);
	return array(
		'update.xml' => updateServerCollectionXml($stable[0]['version']),
		'update-pkg.xml' => updateServerDetailsXml($newest, $fetch),
	);
}

function updateServerDownload($url)
{
	$context = stream_context_create(array('http' => array('timeout' => 60, 'follow_location' => 1)));
	return @file_get_contents($url, false, $context);
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__)
{
	if ($argc !== 3)
	{
		fwrite(STDERR, "Usage: php {$argv[0]} RELEASES.json OUTPUT_DIRECTORY\n");
		exit(2);
	}
	[, $releasesFile, $outputDir] = $argv;
	$releases = json_decode((string) @file_get_contents($releasesFile), true);
	if (!is_array($releases))
	{
		fwrite(STDERR, "$releasesFile is not the JSON of a list of releases\n");
		exit(1);
	}
	try
	{
		$files = updateServerFiles($releases, 'updateServerDownload');
	}
	catch (RuntimeException $e)
	{
		fwrite(STDERR, 'ERROR: '.$e->getMessage()."\n");
		exit(1);
	}
	if (!is_dir($outputDir) && !mkdir($outputDir, 0777, true))
	{
		fwrite(STDERR, "Cannot create $outputDir\n");
		exit(1);
	}
	foreach ($files as $name => $content)
	{
		file_put_contents($outputDir.'/'.$name, $content);
		echo "Wrote $outputDir/$name\n";
	}
}
