<?php
/*
 * @package BFStop Task Plugin (plg_task_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\Task\Bfstop\Extension;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use Codeling\Plugin\System\Bfstop\Repository\Repositories;
use Codeling\Plugin\System\Bfstop\Service\DailyMaintenance;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Component\Scheduler\Administrator\Event\ExecuteTaskEvent;
use Joomla\Component\Scheduler\Administrator\Task\Status;
use Joomla\Component\Scheduler\Administrator\Traits\TaskPluginTrait;
use Joomla\Event\SubscriberInterface;
use Joomla\Registry\Registry;

/**
 * Runs the daily maintenance of Brute Force Stop - purging what is old, the
 * tables kept below their bounds, the .htaccess file, the log - as a task of
 * Joomla's Task Scheduler, instead of in the request of whichever visitor
 * comes first after a day. All it needs is the system plugin, whose settings
 * it uses and whose services it calls.
 */
final class Bfstop extends CMSPlugin implements SubscriberInterface
{
	use TaskPluginTrait;

	/** the routine of the task: its title and description are PLG_TASK_BFSTOP_MAINTENANCE_TITLE and _DESC */
	public const MaintenanceRoutine = 'bfstop.maintenance';

	private const TASKS_MAP = [
		self::MaintenanceRoutine => [
			'langConstPrefix' => 'PLG_TASK_BFSTOP_MAINTENANCE',
			'method'          => 'maintenance',
		],
	];

	protected $autoloadLanguage = true;

	public static function getSubscribedEvents(): array
	{
		return [
			'onTaskOptionsList' => 'advertiseRoutines',
			'onExecuteTask'     => 'standardRoutineHandler',
		];
	}

	private function maintenance(ExecuteTaskEvent $event): int
	{
		// enabled plugins only: with the system plugin off, the site isn't protected
		// and there is no maintenance of its data to do
		$plugin = PluginHelper::getPlugin('system', 'bfstop');
		if (!$plugin || !class_exists(DailyMaintenance::class))
		{
			$this->logTask('The plugin "System - Brute Force Stop" is not enabled: nothing to do');
			return Status::OK;
		}
		$settings = new Registry($plugin->params);
		$repositories = new Repositories(LoggerHelper::fromSettings($settings));
		if ((new DailyMaintenance($repositories, $settings))->runNow())
		{
			$this->logTask('The maintenance of Brute Force Stop is done');
		}
		else
		{
			$this->logTask('The maintenance of Brute Force Stop is running already: not run again');
		}
		return Status::OK;
	}
}
