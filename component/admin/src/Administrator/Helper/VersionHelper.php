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

class VersionHelper
{
	public static function getVersion($manifest_cache)
	{
		$json = json_decode($manifest_cache);
		return (property_exists($json, "version")) ? $json->version : '';
	}

	public static function checkSameMajorMinor($version1, $version2)
	{
		$ver1arr = explode('.', $version1);
		$ver2arr = explode('.', $version2);
		return count($ver1arr) >= 2 && count($ver2arr) >= 2 && $ver1arr[0] === $ver2arr[0] && $ver1arr[1] === $ver2arr[1];
	}

	// returns null for an extension that cannot be found (caller should
	// treat that as "not installed", not as an empty version string).
	public static function getInstalledVersions()
	{
		$db = Factory::getDbo();

		$query = "SELECT manifest_cache FROM #__extensions WHERE name='plg_system_bfstop'";
		$db->setQuery($query);
		$plugin = $db->loadResult();

		$query = "SELECT manifest_cache FROM #__extensions WHERE name='com_bfstop'";
		$db->setQuery($query);
		$component = $db->loadResult();

		return array(
			'plugin' => $plugin === null ? null : self::getVersion($plugin),
			'component' => $component === null ? null : self::getVersion($component),
		);
	}
}
