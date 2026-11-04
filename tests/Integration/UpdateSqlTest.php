<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Joomla\CMS\Installer\Installer;

/**
 * Runs the update SQL of 2.0.0 through Joomla's installer on tables which
 * already have all of its changes - as an attempt to update again after one
 * which stopped halfway does (see tests/Unit/UpdateSqlTest.php): it has to
 * get through, and record the new schema version.
 */
class UpdateSqlTest extends IntegrationTestCase
{
	protected function emptyTables()
	{
		// not needed here
	}

	private function schemaVersion($extensionId)
	{
		return $this->queryValue('SELECT version_id FROM #__schemas WHERE extension_id='.(int) $extensionId);
	}

	public function testUpdateCanRunAgainOnTablesItAlreadyChanged()
	{
		if ($this->db->getServerType() !== 'mysql')
		{
			$this->markTestSkipped('PostgreSQL is supported from 2.0.0 on, there is no update SQL for it yet');
		}
		$extensionId = (int) $this->queryValue("SELECT extension_id FROM #__extensions WHERE type='plugin' AND element='bfstop'");
		$original = $this->schemaVersion($extensionId);
		$this->assertNotNull($original);
		try
		{
			$this->db->setQuery("UPDATE #__schemas SET version_id='1.4.3' WHERE extension_id=".$extensionId);
			$this->db->execute();

			$root = dirname(__DIR__, 2);
			$manifest = simplexml_load_file($root.'/bfstop.xml');
			$installer = new Installer();
			$installer->setDatabase($this->db);
			$installer->setPath('extension_root', $root);
			$result = $installer->parseSchemaUpdates($manifest->update->schemas, $extensionId);

			$this->assertNotFalse($result, 'an update SQL statement failed, see the "Update" log of the Joomla site');
			$versions = array_map(function ($file) { return basename($file, '.sql'); },
				glob($root.'/sql/updates/*.sql'));
			usort($versions, 'version_compare');
			$this->assertSame(end($versions), $this->schemaVersion($extensionId));
		}
		finally
		{
			$this->db->setQuery('UPDATE #__schemas SET version_id='.$this->db->quote($original).
				' WHERE extension_id='.$extensionId);
			$this->db->execute();
		}
	}
}
