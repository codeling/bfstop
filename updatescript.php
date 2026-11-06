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
use Joomla\CMS\Installer\InstallerScript;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Router\Route;
use Joomla\Database\DatabaseInterface;

class PlgsystembfstopInstallerScript extends InstallerScript
{
	// InstallerScript::preflight() refuses to install on anything older (and
	// to replace a newer version of the plugin with an older one)
	protected $minimumJoomla = '5.0.0';
	protected $minimumPhp = '8.1.0';

	// the version this update replaces, null for an installation
	private $previousVersion = null;

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
	public function preflight($type, $adapter)
	{
		if (!parent::preflight($type, $adapter))
		{
			return false;
		}
		if ($type === 'update')
		{
			$manifest = $this->getItemArray('manifest_cache', '#__extensions', 'name', 'plg_system_bfstop');
			$this->previousVersion = isset($manifest['version']) ? (string) $manifest['version'] : null;
			$this->renameWhitelistTable();
		}
		return true;
	}

	/**
	 * For version 1.4.2, the whitelist table was renamed to allowlist, but only
	 * for updates; new installations kept the old name. This has to happen
	 * before the update SQL, which runs after preflight() but before update()
	 * and changes the allowlist table (MySQL only - PostgreSQL is supported
	 * from 2.0.0 on, so no such table exists there).
	 */
	private function renameWhitelistTable()
	{
		$db = Factory::getContainer()->get(DatabaseInterface::class);
		if ($db->getServerType() !== 'mysql')
		{
			return;
		}
		$prefix = $db->getPrefix();
		$tables = array_map('strtolower', $db->getTableList());
		if (in_array(strtolower($prefix.'bfstop_whitelist'), $tables, true) &&
			!in_array(strtolower($prefix.'bfstop_allowlist'), $tables, true))
		{
			$db->setQuery('RENAME TABLE '.$db->quoteName('#__bfstop_whitelist').
				' TO '.$db->quoteName('#__bfstop_allowlist'));
			$db->execute();
		}
	}

	public function postflight($type, $adapter)
	{
		// only for the update from a version before the settings moved, not
		// for every later update - nor from a test release of 2.0.0 (2.0.0-dev
		// sorts before 2.0.0-alpha1, -beta1 and -rc1)
		if ($type === 'update' && $this->previousVersion !== null &&
			version_compare($this->previousVersion, '2.0.0-dev', '<'))
		{
			$lang = Factory::getApplication()->getLanguage();
			$lang->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
			Factory::getApplication()->enqueueMessage(
				Text::sprintf('PLG_SYSTEM_BFSTOP_UPDATE_2_0_0_HINT', Route::_('index.php?option=com_bfstop&view=settings', false)),
				'warning'
			);
		}
	}

	public function update(InstallerAdapter $adapter)
	{
		$db = Factory::getContainer()->get(DatabaseInterface::class);

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
