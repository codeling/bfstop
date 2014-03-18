<?php
/*
 * @package Brute Force Stop (bfstop) for Joomla! >=2.5
 * @author Bernhard Froehler
 * @copyright (C) 2012-2014 Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;
jimport('joomla.log.log');

class plgsystembfstopInstallerScript
{
	private $oldVersion;
	private $newVersion;

	public function install($parent)   { }
	public function uninstall($parent) { }
	public function postflight($type, $parent) { }

	public function preflight($type, $parent)  {
		$this->newVersion = $parent->get('manifest')->version;
		$manifestCache = $this->getSettings('manifest_cache');
		$this->oldVersion = $this->getParam($manifestCache, 'version', $this->newVersion);
	}

	public function update($parent)
	{
		if (version_compare($this->oldVersion, "0.9.11") < 0)
		{
			echo "Updating existing data to the new version ".
				"$this->newVersion...<br />";
			$settings = $this->getSettings('params');
			if (version_compare($this->oldVersion, "0.9.9") < 0) {
				// blockDuration was introduced with version 0.9.9;
				// versions before always blocked an unlimited time
				$duration = 0;
			} else {
				$duration = $this->getParam($settings, 'blockDuration', 0);
			}
			echo "Updating block duration of existing blocked IP".
				" addresses to the currently configured duration of ".
				(($duration==0)
					? "unlimited"
					: "$duration minutes").
				"....";
			$updateResult = $this->updateDuration($duration);
			echo ((($updateResult === false)
				? 'Failed (all blocks will keep the new default'
					.'value of unlimited)!'
				: 'Success!'
				).'<br />');
			echo ("Migrating from simple log on/off switch to loglevel setting...");
			$updateResult = $this->updateLogLevel($settings);
			echo ((($updateResult === false)
				? 'Failed (please check the plugin settings manually!)'
				: 'Success!').'<br />');
		}
	}

	private function updateDuration($duration)
	{
		$db = JFactory::getDBO();
		$sql = "UPDATE #__bfstop_bannedip SET duration=$duration WHERE duration=0";
		$db->setQuery($sql);
		return $db->execute();
	}

	private function updateLogLevel($settings)
	{
		$logging = false;
		if (array_key_exists('loggingEnabled', $settings)) {
			$logging = $settings['loggingEnabled'];
			unset($settings['loggingEnabled']);
		}
		$settings['logLevel'] = strval($logging
			? JLog::DEBUG
			: 0); // logging disabled
		return $this->writeSettings($settings);
	}

	private function getSettings($column) {
		$db = JFactory::getDBO();
		$sql = "SELECT $column FROM #__extensions WHERE name = 'plg_system_bfstop'";
		$db->setQuery($sql);
		$rawSettings = $db->loadResult();
		return (is_null($rawSettings))
			? array()
			: json_decode($rawSettings, true);
	}

	private function writeSettings($settings) {
		$db = JFactory::getDBO();
		$sql = "UPDATE #__extensions SET params='".json_encode($settings)."'".
			" WHERE name = 'plg_system_bfstop'";
		$db->setQuery($sql);
		return $db->execute();
	}

	private function getParam($settings, $name, $defaultValue)
	{
		return array_key_exists($name, $settings)
			? $settings[$name]
			: $defaultValue ;
	}
}
