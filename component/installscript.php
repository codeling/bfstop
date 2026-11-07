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
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;
use Joomla\Filesystem\Folder;

class com_bfstopInstallerScript extends InstallerScript
{
	// InstallerScript::preflight() refuses to install on anything older (and
	// to replace a newer version of the component with an older one)
	protected $minimumJoomla = '5.0.0';
	protected $minimumPhp = '8.1.0';

	/**
	 * @param   InstallerAdapter  $adapter  The object responsible for running this script
	 */
	public function __construct(InstallerAdapter $adapter)
	{
	}
	public function update(InstallerAdapter $adapter)
	{
		$bfstopPath = JPATH_ADMINISTRATOR."/components/com_bfstop/";
		$oldFolders = array( "views/whitelist", "views/whiteip" );
		$oldFiles = array( "models/whitelist.php", "models/whiteip.php" );
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
	public function postflight($type, $adapter)
	{
		// on an update, the plugin says what there is to review (if anything)
		if ($type !== 'install')
		{
			return;
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
	}
}
