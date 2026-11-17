<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Usage: php tests/lint/check-workflows.php
//
// Every action a GitHub Actions workflow uses has to be pinned to the full
// commit SHA of a release, with the release in a comment:
//
//   - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
//
// A tag like @v7 can be moved by whoever controls the action's repository (or
// whoever took it over): the next run of our workflows would run what they
// put there, with this repository's token and in its checkouts. Dependabot
// (github-actions in .github/dependabot.yml) proposes the updates of pinned
// actions. Kept identical in the com_bfstop repository.
//
// Exits with status 1 if a reference is not pinned.

$root = dirname(__DIR__, 2);
$files = array_merge(glob($root.'/.github/workflows/*.yml'), glob($root.'/.github/workflows/*.yaml'),
	glob($root.'/.github/actions/*/action.yml'));
if (count($files) === 0)
{
	fwrite(STDERR, "No workflow files found in $root/.github\n");
	exit(1);
}
$errors = 0;
$references = 0;
foreach ($files as $file)
{
	foreach (file($file) as $number => $line)
	{
		if (!preg_match('/^\s*(?:-\s*)?uses:\s*(\S+)(.*)$/', $line, $m))
		{
			continue;
		}
		$name = $file;
		$name = substr($name, strlen($root) + 1).':'.($number + 1);
		$target = $m[1];
		if (strpos($target, './') === 0)
		{
			continue; // an action of this repository
		}
		++$references;
		if (!preg_match('#^[\w.-]+/[\w./-]+@[0-9a-f]{40}$#', $target))
		{
			echo "ERROR: $name: '$target' is not pinned to a commit SHA\n";
			++$errors;
		}
		elseif (!preg_match('/^\s*#\s*v?\d+\.\d+/', $m[2]))
		{
			echo "ERROR: $name: '$target' has no comment naming the release (# v1.2.3)\n";
			++$errors;
		}
	}
}
echo "$references action reference(s) in ".count($files)." file(s) checked, $errors error(s)\n";
exit($errors > 0 ? 1 : 0);
