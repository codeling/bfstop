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

	// the .htaccess file whose block section of an earlier version could not
	// be replaced, see replaceLegacyHtaccessSection()
	private $htaccessNotRewritten = null;

	// the bit of the "enabledForOrigin" setting for the Web Services API
	// (Bfstop::OriginApi - the class of the version being replaced may be the
	// one loaded while this runs)
	private const OriginApi = 4;

	/**
	 * Whether this update replaces a version before 2.0.0, which kept its
	 * settings in the Plugin Manager and didn't know the API. Not for a test
	 * release of 2.0.0 (2.0.0-dev sorts before 2.0.0-alpha1, -beta1 and -rc1).
	 */
	private function updatesFromBefore200($type)
	{
		return $type === 'update' && $this->previousVersion !== null &&
			version_compare($this->previousVersion, '2.0.0-dev', '<');
	}

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
		if ($this->htaccessNotRewritten !== null)
		{
			Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
			Factory::getApplication()->enqueueMessage(
				Text::sprintf('PLG_SYSTEM_BFSTOP_UPDATE_HTACCESS_NOT_REWRITTEN', htmlspecialchars($this->htaccessNotRewritten, ENT_QUOTES, 'UTF-8')),
				'error'
			);
		}
		// only for the update from a version before the settings moved, not
		// for every later update
		if ($this->updatesFromBefore200($type))
		{
			$lang = Factory::getApplication()->getLanguage();
			$lang->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
			$settingsUrl = Route::_('index.php?option=com_bfstop&view=settings', false);
			Factory::getApplication()->enqueueMessage(
				Text::sprintf('PLG_SYSTEM_BFSTOP_UPDATE_2_0_0_HINT', $settingsUrl),
				'warning'
			);
			// update() switched the protection of the API on, see there
			Factory::getApplication()->enqueueMessage(
				Text::sprintf('PLG_SYSTEM_BFSTOP_UPDATE_2_0_0_API_HINT', $settingsUrl),
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

			$changed = false;
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
				$changed = true;
			}
			// 2.0.0 also protects logins through the Web Services API, which
			// the frontend/backend setting of earlier versions didn't cover:
			// switched on for every site, as it is for a new installation (a
			// setting that was never saved gets the new default anyway).
			// postflight() tells the administrator
			if (is_array($params) && $this->updatesFromBefore200('update') &&
				array_key_exists('enabledForOrigin', $params))
			{
				$params['enabledForOrigin'] = ((int) $params['enabledForOrigin']) | self::OriginApi;
				$changed = true;
			}
			// whatever the blocking mode is now: the file may still hold the
			// section of the time .htaccess blocking was used
			$htaccessPath = (is_array($params) && (string) ($params['htaccessPath'] ?? '') !== '')
				? (string) $params['htaccessPath'] : JPATH_ROOT;
			if (!self::replaceLegacyHtaccessSection(rtrim($htaccessPath, '/\\').'/.htaccess'))
			{
				$this->htaccessNotRewritten = rtrim($htaccessPath, '/\\').'/.htaccess';
			}
			if ($changed)
			{
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

	/**
	 * Whether $value is an IP address, or a network in CIDR notation - all
	 * that may get into a condition of the web server's configuration.
	 */
	private static function isAddressOrNetwork($value)
	{
		$parts = explode('/', (string) $value);
		if (count($parts) > 2 || filter_var($parts[0], FILTER_VALIDATE_IP) === false)
		{
			return false;
		}
		return count($parts) === 1 || (preg_match('/^[0-9]{1,3}\z/', $parts[1]) === 1 &&
			(int) $parts[1] <= (strpos($parts[0], ':') !== false ? 128 : 32));
	}

	/**
	 * Replaces the block section which versions up to 2.0.0 wrote into the
	 * .htaccess file - "<RequireAll> Require all granted, Require not ip ...
	 * </RequireAll>" - by the form the plugin writes now (see the plugin's
	 * HtaccessHelper), keeping the addresses, the 403 message and any lines
	 * added by hand. Apache combines the authorization directives at the top
	 * level of a configuration section with an implicit <RequireAny>, so the
	 * "Require all granted" let everybody who wasn't blocked past every other
	 * access control of the directory (HTTP authentication, "Require ip",
	 * "Require all denied").
	 *
	 * Done here, without the plugin's classes: those of the version being
	 * replaced may be the ones loaded in this request.
	 *
	 * @return bool false if the section is there and the file couldn't be written
	 */
	public static function replaceLegacyHtaccessSection($file)
	{
		if (!is_file($file))
		{
			return true;
		}
		$content = @file_get_contents($file);
		if (!is_string($content))
		{
			return false;
		}
		$lines = explode("\n", $content);
		$begin = null;
		$end = null;
		foreach ($lines as $i => $line)
		{
			if ($begin === null && strpos($line, '# BEGIN BFStop Blocks') !== false)
			{
				$begin = $i;
			}
			elseif ($begin !== null && strpos($line, '# END BFStop Blocks') !== false)
			{
				$end = $i;
				break;
			}
		}
		if ($begin === null || $end === null)
		{
			return true;
		}
		$addresses = array();
		$errorDocument = null;
		$other = array();
		$legacy = false;
		for ($i = $begin + 1; $i < $end; ++$i)
		{
			$line = trim($lines[$i]);
			if ($line === '')
			{
				continue;
			}
			if (in_array($line, array('<RequireAll>', 'Require all granted', '</RequireAll>'), true))
			{
				$legacy = true;
			}
			elseif (strpos($line, 'Require not ip ') === 0)
			{
				$legacy = true;
				$address = substr($line, strlen('Require not ip '));
				if (self::isAddressOrNetwork($address))
				{
					$addresses[] = $address;
				}
			}
			elseif (strpos($line, 'ErrorDocument 403 ') === 0)
			{
				$errorDocument = $line;
			}
			else
			{
				$other[] = rtrim($lines[$i], "\r");
			}
		}
		if (!$legacy)
		{
			return true;
		}
		$section = array();
		// as many addresses per <If> as HtaccessHelper::AddressesPerCondition
		foreach (array_chunk(array_values(array_unique($addresses)), 50) as $chunk)
		{
			$conditions = array();
			foreach ($chunk as $address)
			{
				$conditions[] = "-R '".$address."'";
			}
			$section[] = '<If "'.implode(' || ', $conditions).'">';
			$section[] = 'Require all denied';
			$section[] = '</If>';
		}
		if ($errorDocument !== null)
		{
			$section[] = $errorDocument;
		}
		array_splice($lines, $begin + 1, $end - $begin - 1, array_merge($section, $other));
		$newContent = implode("\n", $lines);

		// replaced as a whole, like HtaccessHelper::write() does
		$target = is_link($file) ? (realpath($file) ?: $file) : $file;
		$temporary = $target.'.bfstop-'.bin2hex(random_bytes(6));
		if (@file_put_contents($temporary, $newContent) === strlen($newContent))
		{
			@chmod($temporary, fileperms($target) & 0777);
			if (@rename($temporary, $target))
			{
				return true;
			}
		}
		@unlink($temporary);
		return @file_put_contents($target, $newContent, LOCK_EX) !== false;
	}
}
