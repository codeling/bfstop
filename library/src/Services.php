<?php
/*
 * @package BFStop Library (lib_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;

/**
 * The library's services, for the DI container of an extension which uses
 * them (see the services/provider.php of the plugins):
 *
 *   Settings::class      the settings (a Registry, see Settings::stored())
 *   LoggerHelper::class  the log, at the level of the settings
 *   Repositories::class  the tables
 *
 * Each get() makes a new one, from the settings as they are then: a
 * long-running process (the scheduler's command line) sees changed settings.
 */
final class Services implements ServiceProviderInterface
{
	public function register(Container $container)
	{
		$container->set(Settings::class, function (Container $container)
		{
			return Settings::stored();
		});
		$container->set(LoggerHelper::class, function (Container $container)
		{
			return LoggerHelper::fromSettings($container->get(Settings::class));
		});
		$container->set(Repositories::class, function (Container $container)
		{
			return new Repositories($container->get(LoggerHelper::class));
		});
	}
}
