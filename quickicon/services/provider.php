<?php
/*
 * @package BFStop Quick Icon Plugin (plg_quickicon_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

defined('_JEXEC') or die;

use Codeling\Plugin\Quickicon\Bfstop\Extension\Bfstop;
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
				$plugin = new Bfstop((array) PluginHelper::getPlugin('quickicon', 'bfstop'));
				$plugin->setApplication(Factory::getApplication());

				return $plugin;
			}
		);
	}
};
