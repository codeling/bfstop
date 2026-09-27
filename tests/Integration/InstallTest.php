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
