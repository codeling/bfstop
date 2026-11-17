<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Registry\Registry;

class LogHelper
{
	public static function getLogger()
	{
		// false if the plugin is disabled: the page of an unblock link and
		// the lists still work then
		$plugin = PluginHelper::getPlugin('system', 'bfstop');
		$params = new Registry($plugin ? $plugin->params : null);
		$loglevel = $params->get('logLevel', Log::ERROR);
		return new LoggerHelper($loglevel);
	}
}
