<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Counts the queries the plugin sends while a fixture script runs, for
// QueryCountTest: every query goes through the database driver's monitor,
// the plugin's own (Repository::prepare()) as well as insertObject() and
// Joomla's. The fixtures start it right before they hand the event to the
// plugin, so what is counted is what the plugin does with it.

use Joomla\CMS\Factory;
use Joomla\Database\DatabaseInterface;
use Joomla\Database\QueryMonitorInterface;

final class QueryCounter implements QueryMonitorInterface
{
	private array $queries = array();

	/**
	 * Starts counting, if the script was called with --count-queries, and
	 * prints the queries when it ends (also after the plugin's exit(), which
	 * ends a blocked request).
	 */
	public static function startIfAsked(array $argv): void
	{
		if (!in_array('--count-queries', $argv, true))
		{
			return;
		}
		$counter = new self();
		Factory::getContainer()->get(DatabaseInterface::class)->setMonitor($counter);
		register_shutdown_function(function () use ($counter)
		{
			echo $counter->report();
		});
	}

	public function startQuery(string $sql, ?array $boundParams = null): void
	{
		$this->queries[] = preg_replace('/\s+/', ' ', $sql);
	}

	public function stopQuery(): void
	{
	}

	/** "QUERY: <sql>" for each query, then "QUERIES: <number>" */
	public function report(): string
	{
		$out = '';
		foreach ($this->queries as $sql)
		{
			$out .= "\nQUERY: ".$sql;
		}
		return $out."\nQUERIES: ".count($this->queries)."\n";
	}
}
