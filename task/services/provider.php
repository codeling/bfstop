<?php
/*
 * @package BFStop Task Plugin (plg_task_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\DailyMaintenance;
use Codeling\Library\Bfstop\Services;
use Codeling\Library\Bfstop\Settings;
use Codeling\Plugin\Task\Bfstop\Extension\Bfstop;
use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;

return new class () implements ServiceProviderInterface {
	public function register(Container $container)
	{
		// the library's services (see Codeling\Library\Bfstop\Services)
		if (class_exists(Services::class))
		{
			$container->registerServiceProvider(new Services());
		}
		$container->set(
			PluginInterface::class,
			function (Container $container) {
				// the maintenance as the settings are when the task runs; null
				// without the library
				$maintenance = function () use ($container) {
					return $container->has(Repositories::class)
						? new DailyMaintenance($container->get(Repositories::class), $container->get(Settings::class))
						: null;
				};
				$plugin = new Bfstop((array) PluginHelper::getPlugin('task', 'bfstop'), $maintenance);
				$plugin->setApplication(Factory::getApplication());

				return $plugin;
			}
		);
	}
};
