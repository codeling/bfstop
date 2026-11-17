<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Installer\InstallerAdapter;
use Joomla\CMS\Installer\InstallerScript;
use Joomla\CMS\Installer\InstallerScriptInterface;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;
use Joomla\Filesystem\Folder;

/**
 * Joomla takes the instance this file returns (see the end); the class keeps
 * the name of the legacy form, which Joomla looks for if the file has been
 * loaded before. InstallerScript gives preflight() its checks.
 */
class com_bfstopInstallerScript extends InstallerScript implements InstallerScriptInterface
{
	// InstallerScript::preflight() refuses to install on anything older (and
	// to replace a newer version of the component with an older one)
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

	public function uninstall(InstallerAdapter $adapter): bool
	{
		return true;
	}

	public function update(InstallerAdapter $adapter): bool
	{
		$bfstopPath = JPATH_ADMINISTRATOR."/components/com_bfstop/";
		$oldFolders = array( "views/whitelist", "views/whiteip" );
		// config.xml: the "Options" page (com_config) is gone since 2.0.0 - it
		// would save the component's params, which hold the settings, with
		// only its permissions; they are part of the settings page now
		$oldFiles = array( "models/whitelist.php", "models/whiteip.php", "config.xml" );
		foreach ($oldFolders as $folder)
		{
			if (file_exists($bfstopPath.$folder) && is_dir($bfstopPath.$folder))
			{
				Folder::delete($bfstopPath.$folder);
			}
		}
		foreach ($oldFiles as $file)
		{
			if (file_exists($bfstopPath.$file))
			{
				unlink($bfstopPath.$file);
			}
		}
		return true;
	}

	public function postflight(string $type, InstallerAdapter $adapter): bool
	{
		// on an update, the plugin says what there is to review (if anything)
		if ($type !== 'install')
		{
			return true;
		}
		$lang = Factory::getApplication()->getLanguage();
		$lang->load('com_bfstop', JPATH_ADMINISTRATOR);
		// Route::_() gives an empty string when installing from the command line
		$url = Route::_('index.php?option=com_bfstop&view=settings', false);
		$message = Text::sprintf('COM_BFSTOP_INSTALL_HINT', $url !== '' ? $url : 'index.php?option=com_bfstop&view=settings');
		if (PHP_SAPI === 'cli')
		{
			// the console prints messages as they are: no markup there
			$message = html_entity_decode(strip_tags($message), ENT_QUOTES, 'UTF-8');
		}
		Factory::getApplication()->enqueueMessage($message, 'warning');
		return true;
	}
}

return new com_bfstopInstallerScript();
