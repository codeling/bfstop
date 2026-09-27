<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use PHPUnit\Framework\TestCase;

/**
 * Collects what the code under test logs. The plugin catches database
 * exceptions and only logs them (see DatabaseHelper), so every test checks
 * afterwards that no errors were logged - otherwise a broken query would
 * just look like "no matching rows".
 */
class RecordingLogger extends LoggerHelper
{
	public $errors = array();

	public function __construct()
	{
		// deliberately no parent constructor call: don't set up a log file
	}

	public function isEnabled($priority = Log::ERROR)
	{
		return true;
	}

	public function log($msg, $priority)
	{
		if ($priority <= Log::ERROR)
		{
			$this->errors[] = $msg;
		}
	}
}

/**
 * Base class for tests running against a real Joomla site with bfstop
 * installed (see tests/README.md); skipped if JOOMLA_ROOT isn't set.
 */
abstract class IntegrationTestCase extends TestCase
{
	public const Tables = array('failedlogin', 'bannedip', 'unblock',
		'unblock_token', 'allowlist', 'knownip', 'dnscache');

	protected $db;
	protected $logger;

	public static function setUpBeforeClass(): void
	{
		if (!getenv('JOOMLA_ROOT'))
		{
			self::markTestSkipped('JOOMLA_ROOT not set - integration tests need an installed Joomla site, see tests/README.md');
		}
	}

	protected function setUp(): void
	{
		$this->db = Factory::getDbo();
		$this->logger = new RecordingLogger();
		$this->emptyTables();
	}

	protected function emptyTables()
	{
		$existing = array_map('strtolower', $this->db->getTableList());
		foreach (self::Tables as $table)
		{
			if (!in_array($this->db->getPrefix().'bfstop_'.$table, $existing))
			{
				$this->fail('Table #__bfstop_'.$table.' does not exist - the installation did not create it');
			}
			$this->db->setQuery('DELETE FROM #__bfstop_'.$table);
			$this->db->execute();
		}
	}

	protected function assertPostConditions(): void
	{
		$this->assertSame(array(), $this->logger->errors, 'errors were logged');
	}

	/** 'Y-m-d H:i:s' timestamp $minutes ago */
	protected static function minutesAgo($minutes)
	{
		return date('Y-m-d H:i:s', time() - $minutes * 60);
	}

	/** inserts a row, returns the new id if $key is given */
	protected function insert($table, array $row, $key = null)
	{
		$object = (object) $row;
		$this->db->insertObject($table, $object, $key);
		return $key ? (int) $object->$key : null;
	}

	protected function queryValue($sql)
	{
		$this->db->setQuery($sql);
		return $this->db->loadResult();
	}

	protected function getPluginParams()
	{
		return $this->queryValue("SELECT params FROM #__extensions WHERE type='plugin' AND element='bfstop'");
	}

	protected function setPluginParams($params)
	{
		$this->db->setQuery('UPDATE #__extensions SET params='.$this->db->quote($params).
			", enabled=1 WHERE type='plugin' AND element='bfstop'");
		$this->db->execute();
	}
}
