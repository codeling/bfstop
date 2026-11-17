<?php
/*
 * @package BFStop Task Plugin (plg_task_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Installer\InstallerAdapter;
use Joomla\CMS\Installer\InstallerScript;
use Joomla\CMS\Installer\InstallerScriptInterface;
use Joomla\Database\DatabaseInterface;

/**
 * Installs the task plugin switched on, and its task in Joomla's Task
 * Scheduler: once, when the plugin is installed (also by the update from a
 * version of Brute Force Stop which didn't have it), not again by later
 * updates - an administrator who switched the task off or deleted it has to
 * stay in charge. Without the task, a visitor's request runs the maintenance
 * once it didn't run for two days (see MaintenanceSchedule in the system
 * plugin), so a site which can't have the task is looked after as well.
 *
 * Joomla takes the instance this file returns (see the end); the class keeps
 * the name of the legacy form, which Joomla looks for if the file has been
 * loaded before.
 */
class PlgtaskbfstopInstallerScript extends InstallerScript implements InstallerScriptInterface
{
	protected $minimumJoomla = '5.4.0';
	protected $minimumPhp = '8.1.0';

	/** the routine of the plugin, see Codeling\Plugin\Task\Bfstop\Extension\Bfstop */
	public const Routine = 'bfstop.maintenance';

	public function preflight($type, $adapter): bool
	{
		return (bool) parent::preflight($type, $adapter);
	}

	public function install(InstallerAdapter $adapter): bool
	{
		$db = Factory::getContainer()->get(DatabaseInterface::class);
		try
		{
			// plugins install disabled; a task is of no use without it
			$query = $db->createQuery()
				->update($db->quoteName('#__extensions'))
				->set($db->quoteName('enabled') . ' = 1')
				->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
				->where($db->quoteName('folder') . ' = ' . $db->quote('task'))
				->where($db->quoteName('element') . ' = ' . $db->quote('bfstop'));
			$db->setQuery($query);
			$db->execute();
			self::createTask($db);
		}
		catch (\Throwable $e)
		{
			// no scheduler tables (the component is a core part of Joomla, but may
			// be broken): the requests take care of the maintenance, see above
		}
		return true;
	}

	public function update(InstallerAdapter $adapter): bool
	{
		return true;
	}

	public function uninstall(InstallerAdapter $adapter): bool
	{
		try
		{
			$db = Factory::getContainer()->get(DatabaseInterface::class);
			$query = $db->createQuery()
				->delete($db->quoteName('#__scheduler_tasks'))
				->where($db->quoteName('type') . ' = ' . $db->quote(self::Routine));
			$db->setQuery($query);
			$db->execute();
		}
		catch (\Throwable $e)
		{
			// a task which can't be removed is not run any more (no plugin to run it)
		}
		return true;
	}

	public function postflight(string $type, InstallerAdapter $adapter): bool
	{
		return true;
	}

	/**
	 * Adds the daily maintenance task to the Task Scheduler, if there is none:
	 * enabled, every 24 hours, due now - so that it runs as soon as the
	 * scheduler does, whether that is its lazy mode (a visitor's browser asks for
	 * it, in a request of its own), a web cron job or the command line.
	 *
	 * Written as the Task Scheduler's own tables hold a task which was made in
	 * its backend: the rules in the form of the backend and as processed
	 * (cron_rules), the same notifications as for Joomla's own tasks.
	 *
	 * @return bool whether the task was added
	 */
	public static function createTask(DatabaseInterface $db): bool
	{
		$query = $db->createQuery()
			->select('COUNT(*)')
			->from($db->quoteName('#__scheduler_tasks'))
			->where($db->quoteName('type') . ' = ' . $db->quote(self::Routine));
		$db->setQuery($query);
		if ((int) $db->loadResult() > 0)
		{
			return false;
		}
		$now = gmdate('Y-m-d H:i:s');
		$task = new \stdClass();
		$task->title = 'Brute Force Stop maintenance';
		$task->type = self::Routine;
		$task->execution_rules = json_encode(array('rule-type' => 'interval-hours', 'interval-hours' => '24',
			'exec-day' => '01', 'exec-time' => '03:00'));
		$task->cron_rules = json_encode(array('type' => 'interval', 'exp' => 'PT24H'));
		$task->state = 1;
		$task->next_execution = $now;
		$task->params = json_encode(array('individual_log' => false, 'log_file' => '', 'notifications' => array(
			'success_mail' => '0', 'failure_mail' => '1', 'fatal_failure_mail' => '1', 'orphan_mail' => '1')));
		$task->created = $now;
		$task->created_by = (int) (Factory::getApplication()->getIdentity()->id ?? 0);
		return $db->insertObject('#__scheduler_tasks', $task);
	}
}

return new PlgtaskbfstopInstallerScript();
