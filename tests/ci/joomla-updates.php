<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Finds newer Joomla! releases for the matrix of .github/workflows/ci.yml and
// applies them; used by .github/workflows/joomla-versions.yml.
//
//   php tests/ci/joomla-updates.php plan RELEASES.json
//       RELEASES.json is the answer of the GitHub API for
//       /repos/joomla/joomla-cms/releases. Prints a JSON plan:
//         bumps:     a newer patch release of a version in the matrix
//                    (same major.minor) - safe to take over automatically
//         new_lines: a release of a newer minor/major line than any in the
//                    matrix - whether to support it is a decision, not a bump
//   php tests/ci/joomla-updates.php apply FROM TO SHA256
//       replaces version FROM by TO in the matrix and adds the checksum of TO
//       to tests/ci/joomla-checksums.sha256 (the entry of FROM stays: the
//       workflow of com_bfstop installs through the same checksum file)
//
// Only stable releases with a full package are considered.

const JoomlaUpdatesPackage = 'Joomla_%s-Stable-Full_Package.tar.gz';

/** @return string[] the Joomla! versions of the matrix, ascending */
function matrixVersions($workflow)
{
	preg_match_all('/\bjoomla:\s*(\d+\.\d+\.\d+)\b/', $workflow, $matches);
	$versions = array_values(array_unique($matches[1]));
	usort($versions, 'version_compare');
	return $versions;
}

/** @return array version => asset digest ('' if the API gives none) of the stable releases with a full package */
function stableReleases(array $releases)
{
	$stable = array();
	foreach ($releases as $release)
	{
		$tag = $release['tag_name'] ?? '';
		if (!empty($release['draft']) || !empty($release['prerelease']) || !preg_match('/^\d+\.\d+\.\d+$/', $tag))
		{
			continue;
		}
		foreach ($release['assets'] ?? array() as $asset)
		{
			if (($asset['name'] ?? '') === sprintf(JoomlaUpdatesPackage, $tag))
			{
				$digest = $asset['digest'] ?? '';
				$stable[$tag] = preg_match('/^sha256:([0-9a-f]{64})$/', $digest, $m) ? $m[1] : '';
			}
		}
	}
	return $stable;
}

function line($version)
{
	return implode('.', array_slice(explode('.', $version), 0, 2));
}

function plan(array $matrix, array $stable)
{
	$versions = array_keys($stable);
	usort($versions, 'version_compare');
	$bumps = array();
	$lines = array();
	foreach ($matrix as $current)
	{
		$newest = $current;
		foreach ($versions as $candidate)
		{
			if (line($candidate) === line($current) && version_compare($candidate, $newest, '>'))
			{
				$newest = $candidate;
			}
		}
		if ($newest !== $current)
		{
			$bumps[] = array('from' => $current, 'to' => $newest, 'digest' => $stable[$newest]);
		}
	}
	// lines newer than any in the matrix; for each one its newest patch release
	$newest = end($matrix);
	foreach ($versions as $candidate)
	{
		$known = false;
		foreach ($matrix as $current)
		{
			$known = $known || line($current) === line($candidate);
		}
		if (!$known && version_compare($candidate, $newest, '>'))
		{
			$lines[line($candidate)] = $candidate;
		}
	}
	$newLines = array();
	foreach ($lines as $line => $version)
	{
		$newLines[] = array('line' => $line, 'version' => $version);
	}
	return array('matrix' => $matrix, 'bumps' => $bumps, 'new_lines' => $newLines);
}

/** @return array(string, string) workflow and checksum file with $to instead of $from */
function apply($workflow, $checksums, $from, $to, $sha256)
{
	foreach (array($from, $to) as $version)
	{
		if (!preg_match('/^\d+\.\d+\.\d+$/', $version))
		{
			throw new InvalidArgumentException("Not a version: $version");
		}
	}
	if (!preg_match('/^[0-9a-f]{64}$/', $sha256))
	{
		throw new InvalidArgumentException('Not a SHA-256');
	}
	if (line($from) !== line($to) || version_compare($to, $from, '<='))
	{
		throw new InvalidArgumentException("$to is not a newer release of the $from line");
	}
	$workflow = preg_replace('/\bjoomla:(\s*)'.preg_quote($from, '/').'\b/', 'joomla:${1}'.$to, $workflow, -1, $count);
	if ($count === 0)
	{
		throw new InvalidArgumentException("Joomla $from is not in the matrix");
	}
	$package = sprintf(JoomlaUpdatesPackage, $to);
	if (strpos($checksums, $package) !== false)
	{
		throw new InvalidArgumentException("$package already has a checksum");
	}
	$old = sprintf(JoomlaUpdatesPackage, $from);
	$entry = $sha256.'  '.$package;
	$checksums = preg_replace('/^[0-9a-f]{64}  '.preg_quote($old, '/').'$/m', '$0'."\n".$entry, $checksums, 1, $count);
	if ($count !== 1)
	{
		throw new InvalidArgumentException("$old has no checksum entry to put the new one behind");
	}
	// how it was checked, behind the notes of the other versions
	$major = explode('.', $to)[0];
	$note = "#  $to  taken from the GitHub release asset by the joomla-versions workflow;\n"
		."#         compare with downloads.joomla.org/cms/joomla$major/".str_replace('.', '-', $to);
	$checksums = preg_replace('/^(?!#)/m', $note."\n", $checksums, 1);
	return array($workflow, $checksums);
}

function main(array $argv)
{
	$root = dirname(__DIR__, 2);
	$workflowFile = $root.'/.github/workflows/ci.yml';
	$checksumFile = $root.'/tests/ci/joomla-checksums.sha256';
	$command = $argv[1] ?? '';
	if ($command === 'plan' && count($argv) === 3)
	{
		$releases = json_decode(file_get_contents($argv[2]), true);
		if (!is_array($releases))
		{
			fwrite(STDERR, "$argv[2] is not a list of releases\n");
			return 2;
		}
		echo json_encode(plan(matrixVersions(file_get_contents($workflowFile)), stableReleases($releases)), JSON_PRETTY_PRINT)."\n";
		return 0;
	}
	if ($command === 'apply' && count($argv) === 5)
	{
		try
		{
			list($workflow, $checksums) = apply(file_get_contents($workflowFile), file_get_contents($checksumFile),
				$argv[2], $argv[3], $argv[4]);
		}
		catch (InvalidArgumentException $e)
		{
			fwrite(STDERR, $e->getMessage()."\n");
			return 1;
		}
		file_put_contents($workflowFile, $workflow);
		file_put_contents($checksumFile, $checksums);
		return 0;
	}
	fwrite(STDERR, "Usage: joomla-updates.php plan RELEASES.json | apply FROM TO SHA256\n");
	return 2;
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__)
{
	exit(main($argv));
}
