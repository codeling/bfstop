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

class VersionHelper
{
	/**
	 * The version in the manifest cache $manifest_cache (JSON) of an
	 * extension, '' if it has none - also if the cache is empty or no JSON
	 * object (json_decode() gives null then, which property_exists() throws
	 * a TypeError for).
	 */
	public static function getVersion($manifest_cache)
	{
		$json = json_decode((string) $manifest_cache);
		return (is_object($json) && isset($json->version) && is_scalar($json->version)) ? (string) $json->version : '';
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
		$db = Factory::getContainer()->get(DatabaseInterface::class);
		$manifest = function ($name) use ($db)
		{
			$query = $db->createQuery()
				->select($db->quoteName('manifest_cache'))
				->from($db->quoteName('#__extensions'))
				->where($db->quoteName('name').' = :name')
				->bind(':name', $name);
			$db->setQuery($query);
			return $db->loadResult();
		};
		$plugin = $manifest('plg_system_bfstop');
		$component = $manifest('com_bfstop');
		return array(
			'plugin' => $plugin === null ? null : self::getVersion($plugin),
			'component' => $component === null ? null : self::getVersion($component),
		);
	}
}
