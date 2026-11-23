<?php
/*
 * @package BFStop Console Plugin (plg_console_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\Console\Bfstop\Extension;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Settings;
use Codeling\Plugin\Console\Bfstop\Command\SetupCommand;
use Codeling\Plugin\Console\Bfstop\Command\StatusCommand;
use Codeling\Plugin\Console\Bfstop\Command\UnblockCommand;
use Joomla\Application\ApplicationEvents;
use Joomla\Application\Event\ApplicationEvent;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Console\Application as ConsoleApplication;
use Joomla\Event\SubscriberInterface;

/**
 * The console commands of Brute Force Stop (php cli/joomla.php): for sites
 * installed or updated from the command line, automation, and recovering
 * from a lockout. Joomla's console imports the plugins of the group
 * "console" before it runs, and they add their commands when it starts
 * (ApplicationEvents::BEFORE_EXECUTE) - the system plugin can't, it stays
 * disabled until the setup is done.
 */
final class Bfstop extends CMSPlugin implements SubscriberInterface
{
	public static function getSubscribedEvents(): array
	{
		// without the library the commands could do nothing
		if (!class_exists(Settings::class))
		{
			return array();
		}
		return array(ApplicationEvents::BEFORE_EXECUTE => 'registerCommands');
	}

	public function registerCommands(ApplicationEvent $event): void
	{
		$app = $event->getApplication();
		if (!$app instanceof ConsoleApplication)
		{
			return;
		}
		$app->addCommand(new StatusCommand());
		$app->addCommand(new SetupCommand());
		$app->addCommand(new UnblockCommand());
	}
}
