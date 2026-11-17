<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Services;
use Codeling\Library\Bfstop\Settings;
use Codeling\Plugin\System\Bfstop\Extension\Bfstop;
use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;

return new class () implements ServiceProviderInterface {
	public function register(Container $container)
	{
		// the library's services (see Codeling\Library\Bfstop\Services);
		// without the library, the plugin does nothing (see
		// Bfstop::getSubscribedEvents()) rather than break every request
		$library = class_exists(Services::class);
		if ($library)
		{
			$container->registerServiceProvider(new Services());
		}
		$container->set(
			PluginInterface::class,
			function (Container $container) use ($library) {
				// the plugin's params are the settings of BFStop, which are the
				// component's (see Settings)
				$config = (array) PluginHelper::getPlugin('system', 'bfstop');
				if ($library)
				{
					$config['params'] = $container->get(Settings::class);
				}
				// Joomla gives the plugin its dispatcher when it imports it
				// (PluginHelper::import()); passing it to the constructor is
				// deprecated since Joomla 5.4 and ends with 7.0
				$plugin = new Bfstop($config);
				$plugin->setApplication(Factory::getApplication());

				return $plugin;
			}
		);
	}
};
