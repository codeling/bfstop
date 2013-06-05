<?php
defined('_JEXEC') or die;

class plgsystembfstopInstallerScript
{
	private $oldVersion;
	private $newVersion;

	public function install($parent)   { }
	public function uninstall($parent) { }
	public function postflight($type, $parent) { }

	public function preflight($type, $parent)  {
		$this->newVersion = $parent->get('manifest')->version;
		$this->oldVersion = $this->getParam('version', 'manifest_cache', $this->newVersion);
	}

	public function update($parent)
	{
		if (version_compare($this->oldVersion, "0.9.11") < 0)
		{
			echo "Updating existing data to the new version ".
				"$this->newVersion...<br />";
			if (version_compare($this->oldVersion, "0.9.9") < 0) {
				// blockDuration was introduced with version 0.9.9;
				// versions before always blocked an unlimited time
				$duration = 0;
			} else {
				$duration = $this->getParam('blockDuration', 'params', 0);
			}
			echo "Updating block duration of existing blocked IP".
				" addresses to the currently configured duration of ".
				(($duration==0)
					? "unlimited"
					: "$duration minutes").
				"....";
			$updateResult = $this->updateDuration($duration);
			echo ($updateResult === false)
				? 'Failed (all blocks will keep the new default'
					.'value of unlimited)!'
				: 'Success!';
		}
	}

	private function updateDuration($duration)
	{
		$db = JFactory::getDBO();
		$sql = "UPDATE #__bfstop_bannedip SET duration=$duration WHERE duration=0";
		$db->setQuery($sql);
		return $db->execute();
	}

	private function getParam($name, $column, $defaultValue) {
		$db = JFactory::getDbo();
		$sql = "SELECT $column FROM #__extensions WHERE name = 'plg_system_bfstop'";
		$db->setQuery($sql);
		$rawSettings = $db->loadResult();
		if (is_null($rawSettings)) {
			return $defaultValue;
		}
		$settings = json_decode($rawSettings, true);
		return array_key_exists($name, $settings) ? $settings[$name] : $defaultValue ;
	}
}
