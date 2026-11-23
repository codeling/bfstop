<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

/**
 * Checks what Joomla's extension installer did with bfstop.xml (run by
 * tests/ci/install-joomla.sh): Joomla reports success even if it found no
 * install SQL for the database in use (issue #206).
 */
class InstallTest extends IntegrationTestCase
{
	protected function emptyTables()
	{
		// not needed here, and would fail on missing tables before the test does
	}

	public function testAllTablesCreated()
	{
		$prefix = $this->db->getPrefix();
		$existing = array_map('strtolower', $this->db->getTableList());
		foreach (self::Tables as $table)
		{
			$this->assertContains($prefix.'bfstop_'.$table, $existing);
		}
	}

	/**
	 * The columns of each index of a table, e.g. "ipaddress,logtime".
	 */
	public static function indexedColumns($db, $table)
	{
		$name = $db->getPrefix().$table;
		if ($db->getServerType() === 'postgresql')
		{
			$db->setQuery('SELECT indexdef FROM pg_indexes WHERE tablename = '.$db->quote($name));
			return array_map(function ($definition)
			{
				preg_match('/\(([^)]*)\)\s*$/', $definition, $m);
				return str_replace(array('"', ' '), '', $m[1]);
			}, $db->loadColumn());
		}
		$columns = array();
		$db->setQuery('SHOW INDEX FROM '.$db->quoteName($name));
		foreach ($db->loadObjectList() as $row)
		{
			$columns[$row->Key_name][(int) $row->Seq_in_index] = $row->Column_name;
		}
		return array_map(function ($c) { ksort($c); return implode(',', $c); }, array_values($columns));
	}

	public function testLookupsOfFailedLoginsAreIndexed()
	{
		// per address (every failed login), per username (attacks on one account),
		// by time (notifications, purge): with up to 200000 rows, a scan
		// takes 10-200 ms
		$indexes = self::indexedColumns($this->db, 'bfstop_failedlogin');
		foreach (array('ipaddress,logtime', 'username,logtime', 'logtime') as $columns)
		{
			$this->assertContains($columns, $indexes);
		}
	}

	public function testSchemaVersionRecorded()
	{
		$this->db->setQuery("SELECT s.version_id FROM #__extensions e ".
			"LEFT JOIN #__schemas s ON s.extension_id = e.extension_id ".
			"WHERE e.type='plugin' AND e.folder='system' AND e.element='bfstop'");
		$manifest = simplexml_load_file(BFSTOP_PLUGIN_ROOT.'/bfstop.xml');
		$this->assertSame((string) $manifest->version, $this->db->loadResult());
	}

	/**
	 * The system plugin installs disabled (see InstallerScriptTest): the
	 * setup assistant, or the console command bfstop:setup, activates it -
	 * as tests/ci/install-joomla.sh does with "bfstop:setup --no-proxy" for
	 * the sites of the tests. The package installs the quick icon and the
	 * console plugin switched on.
	 */
	public function testTheSetupActivatesThePlugin()
	{
		$enabled = function ($folder)
		{
			return (int) $this->queryValue("SELECT enabled FROM #__extensions WHERE type='plugin' AND folder=".
				$this->db->quote($folder)." AND element='bfstop'");
		};
		$this->assertSame(1, $enabled('quickicon'));
		$this->assertSame(1, $enabled('console'));
		$this->assertSame(1, $enabled('system'), 'tests/ci/install-joomla.sh ran bfstop:setup');

		$settings = $this->getSettings();
		$this->db->setQuery("UPDATE #__extensions SET enabled=0 WHERE type='plugin' AND folder='system' AND element='bfstop'")->execute();
		$this->db->setQuery("DELETE FROM #__bfstop_state WHERE name LIKE 'setup%'")->execute();
		try
		{
			exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg(getenv('JOOMLA_ROOT').'/cli/joomla.php').
				' bfstop:setup --no-proxy -n 2>&1', $lines, $exitCode);
			$this->assertSame(0, $exitCode, implode("\n", $lines));
			$this->assertSame(1, $enabled('system'));
			$state = json_decode((string) $this->queryValue("SELECT value FROM #__bfstop_state WHERE name='setup'"), true);
			$this->assertGreaterThan(time() - 600, (int) ($state['completed'] ?? 0));
		}
		finally
		{
			$this->db->setQuery("UPDATE #__extensions SET enabled=1 WHERE type='plugin' AND folder='system' AND element='bfstop'")->execute();
			self::storeSettings($this->db, $settings);
		}
	}

	/**
	 * The library is installed with the package, before the extensions which
	 * use it, and Joomla loads its classes from its namespace (the
	 * namespace map is what Joomla's autoloader goes by).
	 */
	public function testLibraryInstalledWithItsNamespace()
	{
		$this->db->setQuery("SELECT enabled, package_id, manifest_cache FROM #__extensions ".
			"WHERE type='library' AND element='bfstop'");
		$row = $this->db->loadObject();
		$this->assertNotNull($row, 'lib_bfstop is not installed');
		$this->assertSame(1, (int) $row->enabled);
		$this->assertGreaterThan(0, (int) $row->package_id, 'lib_bfstop is installed by the package');
		$manifest = simplexml_load_file(BFSTOP_LIBRARY_ROOT.'/bfstop.xml');
		$this->assertSame((string) $manifest->version, json_decode($row->manifest_cache)->version);
		$this->assertFileExists(JPATH_LIBRARIES.'/bfstop/src/Repository/Repositories.php');
		$map = require JPATH_ADMINISTRATOR.'/cache/autoload_psr4.php';
		$this->assertSame(array(JPATH_LIBRARIES.'/bfstop/src'), $map['Codeling\\Library\\Bfstop\\'] ?? null);
		$xml = simplexml_load_file(dirname(__DIR__, 2).'/package/pkg_bfstop.xml');
		$this->assertSame('library', (string) $xml->files->file[0]['type'], 'the library comes first in the package');
	}
}
