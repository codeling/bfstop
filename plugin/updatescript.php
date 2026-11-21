<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Cache\CacheControllerFactoryInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Installer\InstallerAdapter;
use Joomla\CMS\Installer\InstallerScript;
use Joomla\CMS\Installer\InstallerScriptInterface;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Router\Route;
use Joomla\Database\DatabaseInterface;

/**
 * Joomla takes the instance this file returns (see the end); the class keeps
 * the name of the legacy form, which Joomla looks for if the file has been
 * loaded before. InstallerScript gives preflight() its checks.
 */
class PlgsystembfstopInstallerScript extends InstallerScript implements InstallerScriptInterface
{
	// InstallerScript::preflight() refuses to install on anything older (and
	// to replace a newer version of the plugin with an older one)
	protected $minimumJoomla = '5.4.0';
	protected $minimumPhp = '8.2.0';

	// the version this update replaces, null for an installation
	private $previousVersion = null;

	// the .htaccess file whose block section of an earlier version could not
	// be replaced, see replaceLegacyHtaccessSection()
	private $htaccessNotRewritten = null;

	// why update() could not migrate the settings and data, if it couldn't
	private $updateFailure = null;

	// the bit of the "enabledForOrigin" setting for the Web Services API
	// (Origin::Api - the class of the version being replaced may be the
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

	public function install(InstallerAdapter $adapter): bool
	{
		// plugins install disabled by default, but bfstop only does anything
		// useful while running, and all its settings now live in the
		// component - so there's nothing left to configure before enabling it.
		$db = Factory::getContainer()->get(DatabaseInterface::class);
		$query = $db->createQuery()
			->update($db->quoteName('#__extensions'))
			->set($db->quoteName('enabled') . ' = 1')
			->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
			->where($db->quoteName('folder') . ' = ' . $db->quote('system'))
			->where($db->quoteName('element') . ' = ' . $db->quote('bfstop'));
		$db->setQuery($query);
		$db->execute();
		// the scheduled task is on its way (it is made by the task plugin, which the
		// package installs next): a request needn't run the maintenance meanwhile
		try
		{
			self::seedMaintenanceState($db, time());
		}
		catch (\Throwable $e)
		{
			// without the table, the first request does it (and cannot store it either)
		}
		return true;
	}

	public function uninstall(InstallerAdapter $adapter): bool
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
		// without the plugin, nothing would ever take an address out of the
		// block section of the .htaccess file again: the web server would
		// refuse them for good
		try
		{
			$file = self::htaccessFile(self::storedSettings(Factory::getContainer()->get(DatabaseInterface::class))['params']);
			if (!self::removeHtaccessSection($file))
			{
				Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
				Factory::getApplication()->enqueueMessage(
					Text::sprintf('PLG_SYSTEM_BFSTOP_UNINSTALL_HTACCESS_NOT_REMOVED', htmlspecialchars($file, ENT_QUOTES, 'UTF-8')),
					'error'
				);
			}
		}
		catch (\Throwable $e)
		{
			// neither may this
		}
		return true;
	}

	/**
	 * The params of the extension $type/$folder/$element as they are stored:
	 * null if it isn't installed, an empty array if it has none.
	 */
	private static function extensionParams($db, $type, $folder, $element)
	{
		$query = $db->createQuery()
			->select($db->quoteName('params'))
			->from($db->quoteName('#__extensions'))
			->where($db->quoteName('type') . ' = ' . $db->quote($type))
			->where($db->quoteName('folder') . ' = ' . $db->quote($folder))
			->where($db->quoteName('element') . ' = ' . $db->quote($element));
		$db->setQuery($query);
		$params = $db->loadResult();
		if ($params === null)
		{
			return null;
		}
		$params = json_decode((string) $params, true);
		return is_array($params) ? $params : array();
	}

	/**
	 * The settings of BFStop as they are stored, and where: since 2.0.0 they
	 * are the component's params (see the library's Settings), before they
	 * were the plugin's.
	 *
	 * @return array 'params' => the settings, 'plugin' => whether they are
	 *               still the plugin's params, 'component' => whether the
	 *               component is installed (whose params they are to be)
	 */
	public static function storedSettings($db)
	{
		$component = self::extensionParams($db, 'component', '', 'com_bfstop');
		$plugin = self::extensionParams($db, 'plugin', 'system', 'bfstop') ?? array();
		// the note of the plugin's (otherwise empty) configuration form
		unset($plugin['settingsMoved']);
		// the plugin's params are emptied when they are moved, so settings
		// there are those of a version before 2.0.0 - which the component's
		// params can't have yet (only what its "Options" page stored)
		return array(
			'params' => empty($plugin) ? ($component ?? array()) : array_merge($component ?? array(), $plugin),
			'plugin' => !empty($plugin),
			'component' => $component !== null,
		);
	}

	/**
	 * Stores the settings $params where they belong: in the component's
	 * params, and takes them out of the plugin's, where they were until
	 * 2.0.0 - or, with no component installed (the package installs it
	 * before the plugin), still in the plugin's.
	 */
	public static function storeSettings($db, array $params, array $stored)
	{
		$json = json_encode((object) $params);
		$update = function ($type, $folder, $element, $value) use ($db)
		{
			$query = $db->createQuery()
				->update($db->quoteName('#__extensions'))
				->set($db->quoteName('params') . ' = ' . $db->quote($value))
				->where($db->quoteName('type') . ' = ' . $db->quote($type))
				->where($db->quoteName('folder') . ' = ' . $db->quote($folder))
				->where($db->quoteName('element') . ' = ' . $db->quote($element));
			$db->setQuery($query);
			$db->execute();
		};
		if (!$stored['component'])
		{
			$update('plugin', 'system', 'bfstop', $json);
			return;
		}
		$update('component', '', 'com_bfstop', $json);
		if ($stored['plugin'])
		{
			$update('plugin', 'system', 'bfstop', '{}');
		}
		// the params of the components may be cached (with the site's caching
		// on): the next requests would go on without the settings
		try
		{
			Factory::getContainer()->get(CacheControllerFactoryInterface::class)
				->createCacheController('callback', array('defaultgroup' => '_system'))->clean('_system');
		}
		catch (\Throwable $e)
		{
			// then the cache expires on its own
		}
	}

	/**
	 * The .htaccess file the plugin writes with the settings $params. A copy
	 * of the default of HtaccessHelper::resolvePath() on purpose: while an
	 * update runs, the classes of the version before may still be loaded,
	 * or the library may not be there yet.
	 */
	private static function htaccessFile($params)
	{
		$htaccessPath = (is_array($params) && (string) ($params['htaccessPath'] ?? '') !== '')
			? (string) $params['htaccessPath'] : JPATH_ROOT;
		return rtrim($htaccessPath, '/\\').'/.htaccess';
	}

	public function preflight($type, $adapter): bool
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

	public function postflight(string $type, InstallerAdapter $adapter): bool
	{
		if ($this->updateFailure !== null)
		{
			Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
			Factory::getApplication()->enqueueMessage(
				Text::sprintf('PLG_SYSTEM_BFSTOP_UPDATE_MIGRATION_FAILED', htmlspecialchars($this->updateFailure, ENT_QUOTES, 'UTF-8'),
					Route::_('index.php?option=com_bfstop&view=settings', false)),
				'error'
			);
		}
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
		return true;
	}

	/**
	 * What the plugin's directory held of the classes which are the
	 * library's (lib_bfstop) since 2.0.0: the update doesn't remove them,
	 * the manifest only names the folder src.
	 */
	private const MovedToLibrary = array(
		'src/Helper',
		'src/Repository',
		'src/Service/BlockPolicy.php',
		'src/Service/BlockService.php',
		'src/Service/DailyMaintenance.php',
		'src/Service/LoginService.php',
		'src/Service/Maintenance.php',
		'src/Service/MaintenanceSchedule.php',
	);

	/**
	 * Removes the files of an earlier version which are the library's now
	 * (see MovedToLibrary) from the plugin's directory $root.
	 */
	public static function removeMovedToLibrary($root)
	{
		foreach (self::MovedToLibrary as $path)
		{
			$path = $root.'/'.$path;
			if (is_dir($path))
			{
				$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
					RecursiveIteratorIterator::CHILD_FIRST);
				foreach ($files as $file)
				{
					$file->isDir() ? @rmdir($file->getPathname()) : @unlink($file->getPathname());
				}
				@rmdir($path);
			}
			elseif (is_file($path))
			{
				@unlink($path);
			}
		}
	}

	public function update(InstallerAdapter $adapter): bool
	{
		$db = Factory::getContainer()->get(DatabaseInterface::class);
		self::removeMovedToLibrary(JPATH_PLUGINS.'/system/bfstop');

		// for 2.0.0, the previously separate blockEnabled/useHtaccess switches
		// and the (never released) two-value blockMode were unified into a
		// single four-value blockMode setting (#187); every real install still
		// has the old pre-2.0 config, so migrate it once into the equivalent
		// unified value
		try
		{
			// the settings: the plugin's params until 2.0.0, which this update
			// moves to the component (see storeSettings())
			$stored = self::storedSettings($db);
			$params = $stored['params'];

			$changed = $stored['plugin'] && $stored['component'];
			// until 2.0.0, requests converted the addresses of the block and allow list
			// to the one spelling lookups depend on, the first one which found the
			// setting "addressesCanonical" missing: done once here, not by a visitor
			if ($this->updatesFromBefore200('update'))
			{
				self::canonicalizeAddresses($db);
			}
			// the plugin's bookkeeping lived in its settings, where whoever wrote it
			// wrote all the settings back as they had read them - and so raced with an
			// administrator saving them: it is a table of its own now
			$lastPurge = 0;
			if (is_array($params))
			{
				foreach (array('lastPurge', 'addressesCanonical') as $internal)
				{
					if (array_key_exists($internal, $params))
					{
						$lastPurge = $internal === 'lastPurge' ? (int) $params[$internal] : $lastPurge;
						unset($params[$internal]);
						$changed = true;
					}
				}
			}
			// the maintenance ran then (never: it is due, but the task has a day for it)
			self::seedMaintenanceState($db, $lastPurge > 0 ? $lastPurge : time());
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
			$htaccessFile = self::htaccessFile($params);
			if (!self::replaceLegacyHtaccessSection($htaccessFile))
			{
				$this->htaccessNotRewritten = $htaccessFile;
			}
			if ($changed)
			{
				self::storeSettings($db, $params, $stored);
			}
		}
		catch (\Throwable $e)
		{
			// the update itself goes on (the files are new, the plugin works
			// with its defaults), but the administrator has to know: the
			// settings may not have been moved or converted. Logged, and
			// told by postflight()
			$this->updateFailure = $e->getMessage();
			Log::add('Brute Force Stop: the update could not migrate the settings and data: '.$e->getMessage(),
				Log::ERROR, 'jerror');
		}
		return true;
	}

	/**
	 * Stores when the maintenance last ran in #__bfstop_state, unless it
	 * says already.
	 */
	public static function seedMaintenanceState($db, $time)
	{
		$query = $db->createQuery()
			->select($db->quoteName('name'))
			->from($db->quoteName('#__bfstop_state'))
			->where($db->quoteName('name') . ' = ' . $db->quote('lastMaintenance'));
		$db->setQuery($query);
		if ($db->loadResult() !== null)
		{
			return;
		}
		$row = new \stdClass();
		$row->name = 'lastMaintenance';
		$row->value = (string) (int) $time;
		$row->changed = gmdate('Y-m-d H:i:s');
		$db->insertObject('#__bfstop_state', $row);
	}

	/**
	 * The one spelling in which addresses and networks are stored in the
	 * block and allow list: IpHelper::canonicalEntry() of the plugin, which
	 * the update can't call (the class of the version being replaced may be
	 * the one loaded in this request) - a test checks that both agree.
	 *
	 * @return string|null null if $value is neither an address nor a network
	 */
	public static function canonicalAddress($value)
	{
		$value = self::unmapped(trim((string) $value));
		if (!self::isAddressOrNetwork($value))
		{
			return null;
		}
		$parts = explode('/', $value);
		$bin = inet_pton($parts[0]);
		if (count($parts) === 1)
		{
			return inet_ntop($bin);
		}
		$bits = (int) $parts[1];
		$mask = str_repeat("\xff", intdiv($bits, 8));
		if ($bits % 8 > 0)
		{
			$mask .= chr((0xff << (8 - $bits % 8)) & 0xff);
		}
		return inet_ntop($bin & str_pad($mask, strlen($bin), "\x00")).'/'.$bits;
	}

	/**
	 * An IPv4-mapped IPv6 address or network (::ffff:203.0.113.5,
	 * ::ffff:203.0.113.0/120) as the IPv4 one: IpHelper::unmapped() of the
	 * plugin, see canonicalAddress().
	 */
	private static function unmapped($value)
	{
		$parts = explode('/', $value, 2);
		$bin = @inet_pton($parts[0]);
		if ($bin === false || strlen($bin) !== 16 || substr($bin, 0, 12) !== str_repeat("\x00", 10)."\xff\xff")
		{
			return $value;
		}
		$ipv4 = inet_ntop(substr($bin, 12));
		if (count($parts) === 1)
		{
			return $ipv4;
		}
		if (!preg_match('/^[0-9]{1,3}\z/', $parts[1]) || (int) $parts[1] < 96 || (int) $parts[1] > 128)
		{
			return $value;
		}
		return $ipv4.'/'.((int) $parts[1] - 96);
	}

	/**
	 * Brings the addresses in the block and allow list into canonical form
	 * (see canonicalAddress()): entries written by earlier versions, or by
	 * hand, may be spelled differently ("2001:DB8::1", "203.0.113.5/24").
	 * Entries which are no address or network are left alone.
	 *
	 * @return int the number of entries changed
	 */
	public static function canonicalizeAddresses($db)
	{
		$changed = 0;
		foreach (array('#__bfstop_bannedip', '#__bfstop_allowlist') as $table)
		{
			$lastId = 0;
			do
			{
				$query = $db->createQuery()
					->select($db->quoteName(array('id', 'ipaddress')))
					->from($db->quoteName($table))
					->where($db->quoteName('id') . ' > ' . (int) $lastId)
					->order($db->quoteName('id') . ' ASC');
				$db->setQuery($query, 0, 5000);
				$rows = $db->loadObjectList();
				foreach ($rows as $row)
				{
					$lastId = (int) $row->id;
					$canonical = self::canonicalAddress($row->ipaddress);
					if ($canonical !== null && $canonical !== $row->ipaddress)
					{
						$update = $db->createQuery()
							->update($db->quoteName($table))
							->set($db->quoteName('ipaddress') . ' = ' . $db->quote($canonical))
							->where($db->quoteName('id') . ' = ' . (int) $row->id);
						$db->setQuery($update);
						$db->execute();
						++$changed;
					}
				}
			}
			while (count($rows) === 5000);
		}
		return $changed;
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
	 * replaced may be the ones loaded in this request. What lets the links of
	 * unblock emails through needs the site's path, which an update from the
	 * command line doesn't know: the plugin's daily maintenance adds it (see
	 * HtaccessHelper::upgradeFormat()).
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
		list($begin, $end) = self::findSection($lines);
		if ($begin === null)
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
		return self::writeFile($file, implode("\n", $lines));
	}

	/**
	 * Whether $line is the <If> of a block the plugin writes: a condition of
	 * nothing but addresses, with the exception of the unblock page or
	 * without (a copy of HtaccessHelper's, see htaccessFile() for why).
	 */
	private static function isBlockCondition($line)
	{
		$terms = "-R '[^']*'(?: \\|\\| -R '[^']*')*";
		$unblockPage = " && !\\(%\\{REQUEST_URI\\} == '[^']*' && %\\{QUERY_STRING\\} =~ /[^/]*/\\)";
		return preg_match('#^<If "(?:'.$terms.'|\\('.$terms.'\\)'.$unblockPage.')">$#', $line) === 1;
	}

	/**
	 * The first and the last line of the block section of the .htaccess file
	 * with the lines $lines (its markers), or two nulls if it has none.
	 *
	 * @return array{0: int|null, 1: int|null}
	 */
	private static function findSection(array $lines)
	{
		$begin = null;
		foreach ($lines as $i => $line)
		{
			if ($begin === null && strpos($line, '# BEGIN BFStop Blocks') !== false)
			{
				$begin = $i;
			}
			elseif ($begin !== null && strpos($line, '# END BFStop Blocks') !== false)
			{
				return array($begin, $i);
			}
		}
		return array(null, null);
	}

	/**
	 * Replaces the content of $file as a whole, like the plugin's
	 * HtaccessHelper::write() does.
	 */
	private static function writeFile($file, $content)
	{
		$target = is_link($file) ? (realpath($file) ?: $file) : $file;
		$temporary = $target.'.bfstop-'.bin2hex(random_bytes(6));
		if (@file_put_contents($temporary, $content) === strlen($content))
		{
			@chmod($temporary, fileperms($target) & 0777);
			if (@rename($temporary, $target))
			{
				return true;
			}
		}
		@unlink($temporary);
		return @file_put_contents($target, $content, LOCK_EX) !== false;
	}

	/**
	 * Takes what the plugin writes out of the block section of the .htaccess
	 * file $file - the conditions with the blocked addresses, the 403
	 * message, and the lines of the form of earlier versions - for the
	 * uninstallation. Lines somebody else wrote into the section stay; a
	 * section without any goes as a whole, with its markers. Done without
	 * the plugin's classes, like replaceLegacyHtaccessSection().
	 *
	 * @return bool false if the section is there and the file couldn't be written
	 */
	public static function removeHtaccessSection($file)
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
		list($begin, $end) = self::findSection($lines);
		if ($begin === null)
		{
			return true;
		}
		$other = array();
		for ($i = $begin + 1; $i < $end; ++$i)
		{
			$line = trim($lines[$i]);
			if (self::isBlockCondition($line) && trim($lines[$i + 1] ?? '') === 'Require all denied' &&
				trim($lines[$i + 2] ?? '') === '</If>' && $i + 2 < $end)
			{
				// a block the plugin wrote
				$i += 2;
				continue;
			}
			if (preg_match('/^<If[\s>]/i', $line))
			{
				// one somebody wrote by hand: kept, up to the </If> which closes it
				for ($depth = 0; $i < $end; ++$i)
				{
					$inner = trim($lines[$i]);
					$depth += (preg_match('/^<If[\s>]/i', $inner) ? 1 : 0) - (strcasecmp($inner, '</If>') === 0 ? 1 : 0);
					$other[] = rtrim($lines[$i], "\r");
					if ($depth <= 0)
					{
						break;
					}
				}
				continue;
			}
			if ($line === '' || strpos($line, 'Require not ip ') === 0 || strpos($line, 'ErrorDocument 403 ') === 0 ||
				in_array($line, array('<RequireAll>', 'Require all granted', '</RequireAll>'), true))
			{
				continue;
			}
			$other[] = rtrim($lines[$i], "\r");
		}
		if (count($other) > 0)
		{
			array_splice($lines, $begin + 1, $end - $begin - 1, $other);
		}
		else
		{
			// the plugin writes an empty line after a section it puts at the
			// beginning of the file
			$length = $end - $begin + 1;
			if (isset($lines[$end + 1]) && trim($lines[$end + 1]) === '' && isset($lines[$end + 2]))
			{
				++$length;
			}
			array_splice($lines, $begin, $length);
		}
		return self::writeFile($file, implode("\n", $lines));
	}
}

return new PlgsystembfstopInstallerScript();
