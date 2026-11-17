<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Service;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\LockHelper;
use Codeling\Library\Bfstop\Repository\StateRepository;

/**
 * When the daily maintenance last ran, and whether a visitor's request has to
 * run it.
 *
 * It is the task of Joomla's Task Scheduler (the task plugin "bfstop"), at
 * its own time and not in the request of any visitor. Only if it didn't run
 * for FallbackAfter - the site doesn't use the scheduler, or its task is
 * gone or switched off - the next request does it, as the plugin did before
 * it had the task.
 *
 * The state table holds when it last ran. Every request asks, so the answer
 * must not cost a query: a stamp file in the temporary directory, which each
 * run touches, says it. Only if that is missing (a fresh temporary directory,
 * or none which can be written) the table is read - once, and the stamp made
 * from it.
 */
class MaintenanceSchedule
{
	/** how long the daily maintenance may be missing before a request runs it: two days */
	public const FallbackAfter = 172800;

	private StateRepository $state;

	public function __construct(StateRepository $state)
	{
		$this->state = $state;
	}

	public static function stampFile(): string
	{
		return HtaccessHelper::lockDirectory().'/bfstop-maintenance-'.LockHelper::siteHash().'.stamp';
	}

	/**
	 * Whether the maintenance was not run for FallbackAfter.
	 */
	public function fallbackDue(?int $now = null): bool
	{
		$now = $now ?? time();
		$stamp = self::stampFile();
		clearstatcache(true, $stamp);
		$time = @filemtime($stamp);
		if ($time === false)
		{
			$stored = $this->state->get(StateRepository::LastMaintenance);
			if ($stored === null || !ctype_digit((string) $stored))
			{
				// never run, as far as anybody knows
				return true;
			}
			$time = (int) $stored;
			@touch($stamp, $time);
		}
		return $now - $time >= self::FallbackAfter;
	}

	/**
	 * Remembers that the maintenance ran at $time.
	 */
	public function recordRun(?int $time = null): void
	{
		$time = $time ?? time();
		$this->state->set(StateRepository::LastMaintenance, $time);
		@touch(self::stampFile(), $time);
	}
}
