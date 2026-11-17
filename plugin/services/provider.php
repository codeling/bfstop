<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Extension\Bfstop;
use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;

return new class () implements ServiceProviderInterface {
	public function register(Container $container)
	{
		$container->set(
			PluginInterface::class,
			function (Container $container) {
				// Joomla gives the plugin its dispatcher when it imports it
				// (PluginHelper::import()); passing it to the constructor is
				// deprecated since Joomla 5.4 and ends with 7.0
				$plugin = new Bfstop((array) PluginHelper::getPlugin('system', 'bfstop'));
				$plugin->setApplication(Factory::getApplication());

				return $plugin;
			}
		);
	}
};
