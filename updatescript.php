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
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;
use Joomla\Database\DatabaseInterface;

class PlgsystembfstopInstallerScript
{
	public function __construct(InstallerAdapter $adapter) {}

	public function install(InstallerAdapter $adapter)
	{
		// plugins install disabled by default, but bfstop only does anything
		// useful while running, and all its settings now live in the
		// component - so there's nothing left to configure before enabling it.
		$db = Factory::getContainer()->get(DatabaseInterface::class);
		$query = $db->getQuery(true)
			->update($db->quoteName('#__extensions'))
			->set($db->quoteName('enabled') . ' = 1')
			->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
			->where($db->quoteName('folder') . ' = ' . $db->quote('system'))
			->where($db->quoteName('element') . ' = ' . $db->quote('bfstop'));
		$db->setQuery($query);
		$db->execute();
	}

	public function uninstall(InstallerAdapter $adapter)
	{
		// the log file holds IP addresses and usernames; don't leave it behind
		try
		{
			$logPath = Factory::getApplication()->get('log_path');
			foreach (array('plg_system_bfstop.log.php', 'plg_system_bfstop.1.log.php') as $file)
			{
				if ($logPath && is_file($logPath.'/'.$file))
				{
					@unlink($logPath.'/'.$file);
				}
			}
		}
		catch (\Throwable $e)
		{
			// a leftover log must not make the uninstallation fail
		}
	}
	public function preflight($type, InstallerAdapter $adapter) {}

	public function postflight($type, InstallerAdapter $adapter)
	{
		if ($type === 'update')
		{
			$lang = Factory::getLanguage();
			$lang->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
			Factory::getApplication()->enqueueMessage(
				Text::sprintf('PLG_SYSTEM_BFSTOP_UPDATE_2_0_0_HINT', Route::_('index.php?option=com_bfstop&view=settings', false)),
				'warning'
			);
		}
	}

	public function update(InstallerAdapter $adapter)
	{
		// for version 1.4.2, whitelist was renamed to allowlist, but only for updates;
		// for new installs, the old name remained, so let's fix this for all installations
		// (MySQL only - PostgreSQL is supported from 2.0.0 on, so no such table exists there):
		$db = Factory::getContainer()->get(DatabaseInterface::class);
		if ($db->getServerType() === 'mysql')
		{
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
//				Log::add("Update ERROR: ".$e->getMessage(), Log::ERROR, 'Update');
			}
		}

		// for 2.0.0, the previously separate blockEnabled/useHtaccess switches
		// and the (never released) two-value blockMode were unified into a
		// single four-value blockMode setting (#187); every real install still
		// has the old pre-2.0 config, so migrate it once into the equivalent
		// unified value
		try
		{
			$query = $db->getQuery(true)
				->select($db->quoteName('params'))
				->from($db->quoteName('#__extensions'))
				->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
				->where($db->quoteName('folder') . ' = ' . $db->quote('system'))
				->where($db->quoteName('element') . ' = ' . $db->quote('bfstop'));
			$db->setQuery($query);
			$params = json_decode((string) $db->loadResult(), true);

			if (is_array($params) && !array_key_exists('blockMode', $params))
			{
				$newMode = 'full';
				if (array_key_exists('blockEnabled', $params) && (string) $params['blockEnabled'] === '0')
				{
					$newMode = 'off';
				}
				elseif (array_key_exists('useHtaccess', $params) && (string) $params['useHtaccess'] === '1')
				{
					$newMode = 'htaccess';
				}
				$params['blockMode'] = $newMode;

				$query = $db->getQuery(true)
					->update($db->quoteName('#__extensions'))
					->set($db->quoteName('params') . ' = ' . $db->quote(json_encode($params)))
					->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
					->where($db->quoteName('folder') . ' = ' . $db->quote('system'))
					->where($db->quoteName('element') . ' = ' . $db->quote('bfstop'));
				$db->setQuery($query);
				$db->execute();
			}
		}
		catch (Exception $e)
		{
			// if the extension row can't be found/updated, there's nothing we can do
//			Log::add("Update ERROR: ".$e->getMessage(), Log::ERROR, 'Update');
		}
	}
}
