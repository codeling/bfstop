<?php
defined('_JEXEC') or die;

class PlgsystembfstopInstallerScript
{
	function install($parent) {}
	function uninstall($parent) {}
	function preflight($type, $parent) {}
	function postflight($type, $parent) {}

	function update($parent)
	{
		// for version 1.4.2, whitelist was renamed to allowlist, but only for updates;
		// for new installs, the old name remained, so let's fix this for all installations:
		$db = JFactory::getDbo();
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
