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
		// per address (every failed login), per username (account throttle),
		// by time (adaptive delay, purge): with up to 200000 rows, a scan
		// takes 10-200 ms
		$indexes = self::indexedColumns($this->db, 'bfstop_failedlogin');
		foreach (array('ipaddress,logtime', 'username,logtime', 'logtime') as $columns)
		{
			$this->assertContains($columns, $indexes);
		}
	}

	public function testPluginEnabledAndSchemaVersionRecorded()
	{
		$this->db->setQuery("SELECT e.enabled, s.version_id FROM #__extensions e ".
			"LEFT JOIN #__schemas s ON s.extension_id = e.extension_id ".
			"WHERE e.type='plugin' AND e.element='bfstop'");
		$row = $this->db->loadObject();
		$this->assertSame(1, (int) $row->enabled);
		$manifest = simplexml_load_file(dirname(__DIR__, 2).'/bfstop.xml');
		$this->assertSame((string) $manifest->version, $row->version_id);
	}
}
