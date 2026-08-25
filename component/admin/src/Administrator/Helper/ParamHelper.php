<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;

class ParamHelper
{
	public static function get($name, $column, $defaultValue)
	{
		$db = Factory::getDbo();
		$sql = "SELECT $column FROM #__extensions WHERE name = 'plg_system_bfstop'";
		$db->setQuery($sql);
		$rawSettings = $db->loadResult();
		$settings = json_decode($rawSettings, true);
		return array_key_exists($name, $settings) ? $settings[$name] : $defaultValue;
	}
}
