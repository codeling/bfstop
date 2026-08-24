<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Installer\InstallerAdapter;

class PlgsystembfstopInstallerScript
{
	public function __construct(InstallerAdapter $adapter) {}
	public function install(InstallerAdapter $adapter) {}
	public function uninstall(InstallerAdapter $adapter) {}
	public function preflight($type, InstallerAdapter $adapter) {}
	public function postflight($type, InstallerAdapter $adapter) {}

	public function update(InstallerAdapter $adapter)
	{
		// for version 1.4.2, whitelist was renamed to allowlist, but only for updates;
		// for new installs, the old name remained, so let's fix this for all installations:
		$db = Factory::getDbo();
		try
		{
			$sql = "SELECT COUNT(*) FROM `#__bfstop_whitelist`";
			$db->setQuery($sql);
			$numEntries = ((int)$db->loadResult());
			$sql = "RENAME TABLE `#__bfstop_whitelist` TO `#__bfstop_allowlist`";
			$db->setQuery($sql);
			$db->execute();
		}
		catch (Exception $e)
		{
			// if table doesn't exist, there's nothing we need to do 
//			Log::add("Update ERROR: ".$e->getMessage(), Log::ERROR, 'Update');
		}
	}
}
