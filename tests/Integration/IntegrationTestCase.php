<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Repository\UnblockTokenRepository;
use Codeling\Library\Bfstop\Service\MaintenanceSchedule;
use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use PHPUnit\Framework\TestCase;

/**
 * Collects what the code under test logs. The plugin catches database
 * exceptions and only logs them (see FailurePolicy), so every test checks
 * afterwards that no errors were logged - otherwise a broken query would
 * just look like "no matching rows".
 */
class RecordingLogger extends LoggerHelper
{
	public $errors = array();
	/** everything logged, as array('message' => ..., 'priority' => ...) */
	public $messages = array();

	public function __construct()
	{
		// deliberately no parent constructor call: don't set up a log file
	}

	public function isEnabled($priority = Log::ERROR)
	{
		return true;
	}

	public function hasMessage($priority, $substring = '')
	{
		foreach ($this->messages as $m)
		{
			if ($m['priority'] === $priority && ($substring === '' || str_contains($m['message'], $substring)))
			{
				return true;
			}
		}
		return false;
	}

	public function log($msg, $priority)
	{
		$this->messages[] = array('message' => $msg, 'priority' => $priority);
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
		'offence', 'unblock_token', 'allowlist', 'knownip', 'dnscache', 'username_stats', 'state');

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
		$this->db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
		$this->logger = new RecordingLogger();
		$this->emptyTables();
		// the maintenance has never run: the first request which asks does it
		@unlink(MaintenanceSchedule::stampFile());
	}

	/**
	 * Makes the daily maintenance look as if it just ran (the state table and
	 * the stamp file say so), so that no request does it.
	 */
	protected function markMaintenanceDone($time = null)
	{
		(new MaintenanceSchedule((new Repositories($this->logger))->state()))->recordRun($time);
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

	/**
	 * inserts a row, returns the new id if $key is given. For unblock tokens
	 * the row is given with the token as it is in the mail; what the table
	 * holds is its hash (see UnblockTokenRepository::hash())
	 */
	protected function insert($table, array $row, $key = null)
	{
		if ($table === '#__bfstop_unblock_token' && isset($row['token']))
		{
			$row['token'] = UnblockTokenRepository::hash($row['token']);
		}
		$object = (object) $row;
		$this->db->insertObject($table, $object, $key);
		return $key ? (int) $object->$key : null;
	}

	protected function queryValue($sql)
	{
		$this->db->setQuery($sql);
		return $this->db->loadResult();
	}

	/**
	 * The settings as they are stored: the component's params (see the
	 * library's Settings).
	 */
	protected function getSettings()
	{
		return $this->queryValue("SELECT params FROM #__extensions WHERE type='component' AND element='com_bfstop'");
	}

	/**
	 * Stores the settings $params (JSON), and enables the plugin.
	 */
	protected function setSettings($params)
	{
		self::storeSettings($this->db, $params);
		$this->db->setQuery("UPDATE #__extensions SET enabled=1 WHERE type='plugin' AND folder='system' AND element='bfstop'");
		$this->db->execute();
	}

	/**
	 * Stores the settings $params (JSON), and makes this process read them
	 * again: Joomla keeps the params of the components it loaded.
	 */
	protected static function storeSettings($db, $params)
	{
		$db->setQuery('UPDATE #__extensions SET params='.$db->quote($params).
			" WHERE type='component' AND element='com_bfstop'");
		$db->execute();
		self::forgetLoadedSettings();
	}

	/** Makes this process read the settings from the database again, see storeSettings(). */
	protected static function forgetLoadedSettings()
	{
		(new \ReflectionProperty(\Joomla\CMS\Component\ComponentHelper::class, 'components'))->setValue(null, array());
	}
}
