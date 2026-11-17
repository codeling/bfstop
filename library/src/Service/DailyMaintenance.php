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
use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Log\Log;
use Joomla\Registry\Registry;

/**
 * The daily maintenance: the .htaccess file, what is purged by age, the
 * tables which are kept below an upper bound, the log file. Run by the task
 * of Joomla's Task Scheduler (plugin plg_task_bfstop), or, as the plugin
 * always did before it had the task, by a request if the task didn't run
 * for two days - see MaintenanceSchedule.
 */
class DailyMaintenance
{
	private Repositories $repositories;
	private Registry $settings;
	private MaintenanceSchedule $schedule;

	/**
	 * @param Registry $settings the settings (see Settings)
	 */
	public function __construct(Repositories $repositories, Registry $settings)
	{
		$this->repositories = $repositories;
		$this->settings = $settings;
		$this->schedule = new MaintenanceSchedule($repositories->state());
	}

	private static function lockFile(): string
	{
		return HtaccessHelper::lockDirectory().'/bfstop-maintenance-'.LockHelper::siteHash().'.lock';
	}

	/**
	 * Runs the maintenance if it wasn't run for two days (see
	 * MaintenanceSchedule) - for the request of a visitor, so that the
	 * question costs nothing if it was.
	 *
	 * @return bool whether it ran
	 */
	public function runIfOverdue(): bool
	{
		return $this->schedule->fallbackDue() && $this->runNow(true);
	}

	/**
	 * Runs the maintenance, unless another request or the task is running
	 * it right now. With $onlyIfOverdue, it is run only if it still wasn't
	 * run for two days once this one has the lock: the one which had it
	 * before may just have done it.
	 *
	 * If no lock can be taken (no writable temporary directory), it is run
	 * without one: every step can be run again, it only costs time.
	 *
	 * @return bool whether it ran
	 */
	public function runNow(bool $onlyIfOverdue = false): bool
	{
		$handle = LockHelper::acquire(self::lockFile(), 0);
		if ($handle === null)
		{
			$this->repositories->logger()->log('The maintenance is running already', Log::DEBUG);
			return false;
		}
		try
		{
			if ($onlyIfOverdue && !$this->schedule->fallbackDue())
			{
				return false;
			}
			$this->run();
			return true;
		}
		finally
		{
			if ($handle)
			{
				LockHelper::release($handle);
			}
		}
	}

	/**
	 * The steps; $this->schedule says it has run in the end.
	 */
	private function run(): void
	{
		$logger = $this->repositories->logger();
		$logger->log('Running the daily maintenance', Log::INFO);
		// before the purge, which deletes the blocks that ran out long
		// ago: without them, their entries couldn't be told from those
		// added by hand
		$this->tidyHtaccess();
		$maintenance = new Maintenance($this->repositories);
		$purgeAge = (int) $this->settings->get('deleteOld', Settings::Defaults['deleteOld']);
		if ($purgeAge > 0)
		{
			$maintenance->purgeOldEntries($purgeAge);
		}
		// regardless of the purge age setting: these are not deleted by age
		$maintenance->keepWithinBounds();
		LoggerHelper::pruneByAge((int) $this->settings->get('logKeepDays', LoggerHelper::DefaultKeepDays));
		$this->schedule->recordRun();
	}

	/**
	 * The maintenance of the .htaccess file, whatever the blocking mode is
	 * now:
	 *
	 * - a block section of an earlier version grants access (see
	 *   HtaccessHelper::LegacyLines), and one which doesn't let the unblock
	 *   page through makes the links of unblock emails lead nowhere: it is
	 *   written in the current form (the update can't, see updatescript.php);
	 * - the web server knows nothing of durations and unblocks: with blocking
	 *   through the file, the addresses whose blocks are over come out of it;
	 *   with another blocking mode, every address the plugin has blocked -
	 *   the entries are left from the time the file blocked, and would turn
	 *   the addresses away for good, see HtaccessHelper::removeStaleBlocks().
	 */
	private function tidyHtaccess(): void
	{
		$logger = $this->repositories->logger();
		$htaccess = new HtaccessHelper(
			HtaccessHelper::resolvePath((string) $this->settings->get('htaccessPath', '')), $logger);
		if (!is_file($htaccess->getFileName()))
		{
			return;
		}
		if (!$htaccess->upgradeFormat())
		{
			$logger->log('Could not write the block section of '.$htaccess->getFileName().' in its current form '.
				'- make the file writable: one of an earlier version lets everybody who isn\'t blocked past the other '.
				'access controls of the directory, and without the current form, the links of unblock emails can\'t be '.
				'followed', Log::ERROR);
		}
		$throughFile = (string) $this->settings->get('blockMode', 'full') === 'htaccess';
		if ($htaccess->removeStaleBlocks($this->repositories->blocks(), $throughFile) === false)
		{
			$logger->log('Could not take the addresses the plugin blocked out of '.$htaccess->getFileName().
				': the web server goes on refusing them - make the file writable', Log::ERROR);
		}
	}
}
