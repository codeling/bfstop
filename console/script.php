<?php
/*
 * @package BFStop Console Plugin (plg_console_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Installer\InstallerAdapter;
use Joomla\CMS\Installer\InstallerScript;
use Joomla\CMS\Installer\InstallerScriptInterface;
use Joomla\Database\DatabaseInterface;

/**
 * Installs the console plugin switched on (plugins install disabled): its
 * commands are how a site installed or updated from the command line is set
 * up, and how an administrator who locked everybody out lifts the block.
 * Once, when it is installed - an administrator who switched it off stays in
 * charge.
 *
 * Joomla takes the instance this file returns (see the end); the class keeps
 * the name of the legacy form, which Joomla looks for if the file has been
 * loaded before.
 */
class PlgconsolebfstopInstallerScript extends InstallerScript implements InstallerScriptInterface
{
	protected $minimumJoomla = '5.4.0';
	protected $minimumPhp = '8.2.0';

	public function preflight($type, $adapter): bool
	{
		return (bool) parent::preflight($type, $adapter);
	}

	public function install(InstallerAdapter $adapter): bool
	{
		$db = Factory::getContainer()->get(DatabaseInterface::class);
		$query = $db->createQuery()
			->update($db->quoteName('#__extensions'))
			->set($db->quoteName('enabled') . ' = 1')
			->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
			->where($db->quoteName('folder') . ' = ' . $db->quote('console'))
			->where($db->quoteName('element') . ' = ' . $db->quote('bfstop'));
		$db->setQuery($query);
		$db->execute();
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

return new PlgconsolebfstopInstallerScript();
