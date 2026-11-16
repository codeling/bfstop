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
use Joomla\Database\DatabaseInterface;

class ParamHelper
{
	/**
	 * A setting of the plugin as it is stored now (the settings are the
	 * plugin's, see Bfstop::DefaultSettings).
	 *
	 * @param string $name         the name of the setting
	 * @param mixed  $defaultValue what is returned if the setting isn't stored
	 */
	public static function get($name, $defaultValue)
	{
		$db = Factory::getContainer()->get(DatabaseInterface::class);
		$query = $db->createQuery()
			->select($db->quoteName('params'))
			->from($db->quoteName('#__extensions'))
			->where($db->quoteName('name').' = :name');
		$extension = 'plg_system_bfstop';
		$query->bind(':name', $extension);
		$db->setQuery($query);
		$rawSettings = $db->loadResult();
		$settings = json_decode((string) $rawSettings, true);
		return (is_array($settings) && array_key_exists($name, $settings)) ? $settings[$name] : $defaultValue;
	}
}
