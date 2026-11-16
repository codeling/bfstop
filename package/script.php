<?php
/*
 * @package BFStop Package (pkg_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Installer\InstallerAdapter;
use Joomla\CMS\Installer\InstallerScript;
use Joomla\CMS\Installer\InstallerScriptInterface;

/**
 * Runs before the plugin and the component are installed: InstallerScript's
 * preflight() refuses Joomla and PHP versions BFStop 2 doesn't run on (a site
 * on Joomla 4 has to stay with BFStop 1.5), before anything is changed.
 * Plugin and component check the same themselves when they are installed
 * on their own. Joomla takes the instance this file returns (the class keeps
 * the name of the legacy form, which Joomla looks for if the file has been
 * loaded before).
 */
class pkg_bfstopInstallerScript extends InstallerScript implements InstallerScriptInterface
{
	protected $minimumJoomla = '5.4.0';
	protected $minimumPhp = '8.1.0';

	// InstallerScript's checks, with the return type InstallerScriptInterface
	// has (InstallerScript's own preflight() has none)
	public function preflight($type, $adapter): bool
	{
		return (bool) parent::preflight($type, $adapter);
	}

	public function install(InstallerAdapter $adapter): bool
	{
		return true;
	}

	public function update(InstallerAdapter $adapter): bool
	{
		return true;
	}

	public function uninstall(InstallerAdapter $adapter): bool
	{
		return true;
	}

	public function postflight(string $type, InstallerAdapter $adapter): bool
	{
		return true;
	}
}

return new pkg_bfstopInstallerScript();
