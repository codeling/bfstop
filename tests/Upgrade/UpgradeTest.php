<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Upgrade;

use Codeling\Bfstop\Tests\Integration\IntegrationTestCase;

/**
 * What the update from the previous release made of a site which used it
 * (set up by tests/ci/upgrade-test.sh, seeded by fixtures/seed.php). Only
 * runs there: UPGRADE_FROM is the version updated from, UPGRADE_LOG the
 * output of the update, BFSTOP_PACKAGE the package updated to.
 */
class UpgradeTest extends IntegrationTestCase
{
	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		if (!getenv('UPGRADE_FROM'))
		{
			self::markTestSkipped('only run by tests/ci/upgrade-test.sh, on a site updated from the previous release');
		}
	}

	protected function emptyTables()
	{
		// the data the previous release left is what is tested
	}

	private static function root()
	{
		return dirname(__DIR__, 2);
	}

	private static function newVersion()
	{
		return (string) simplexml_load_file(BFSTOP_PLUGIN_ROOT.'/bfstop.xml')->version;
	}

	private static function latestSchema()
	{
		$versions = array_map(function ($file) { return basename($file, '.sql'); },
			glob(BFSTOP_PLUGIN_ROOT.'/sql/updates/*.sql'));
		usort($versions, 'version_compare');
		return end($versions);
	}

	private function pluginId()
	{
		return (int) $this->queryValue("SELECT extension_id FROM #__extensions WHERE type='plugin' AND folder='system' AND element='bfstop'");
	}

	private function schemaVersion()
	{
		return $this->queryValue('SELECT version_id FROM #__schemas WHERE extension_id='.$this->pluginId());
	}

	private function installedVersions()
	{
		$this->db->setQuery("SELECT type, manifest_cache FROM #__extensions WHERE ".
			"(type='plugin' AND element='bfstop') OR (type='component' AND element='com_bfstop') OR ".
			"(type='package' AND element='pkg_bfstop')");
		$versions = array();
		foreach ($this->db->loadObjectList() as $row)
		{
			$versions[$row->type] = json_decode($row->manifest_cache, true)['version'] ?? null;
		}
		ksort($versions);
		return $versions;
	}

	/** runs Joomla's CLI installer on a package, returns its exit code */
	private function install($package, &$output = null)
	{
		exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg(getenv('JOOMLA_ROOT').'/cli/joomla.php').
			' extension:install -n --path='.escapeshellarg($package).' 2>&1', $lines, $exitCode);
		$output = implode("\n", $lines);
		return $exitCode;
	}

	/** a request to the site from $ip, see Integration/fixtures/request.php */
	private function request($ip)
	{
		exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg(self::root().'/tests/Integration/fixtures/request.php').
			' '.escapeshellarg($ip).' "" 2>&1', $lines, $exitCode);
		$this->assertSame(0, $exitCode, implode("\n", $lines));
		return implode("\n", $lines);
	}

	public function testEverythingIsUpdated()
	{
		$version = self::newVersion();
		$this->assertSame(array('component' => $version, 'package' => $version, 'plugin' => $version),
			$this->installedVersions());
		$this->assertSame(self::latestSchema(), $this->schemaVersion());
		// an update from the command line, without Joomla's "Behind Load
		// Balancer": the plugin stays enabled (see the setup assistant)
		$this->assertSame(1, (int) $this->queryValue("SELECT enabled FROM #__extensions WHERE type='plugin' AND folder='system' AND element='bfstop'"));
	}

	/**
	 * What the update wrote into the state of the setup assistant: an update,
	 * from which version, that it removed delays which were in use - and no
	 * scenario or headers (the command line has no request to look at).
	 */
	public function testTheUpdateRecordsTheSetupState()
	{
		$setup = json_decode((string) $this->queryValue("SELECT value FROM #__bfstop_state WHERE name='setup'"), true);
		$this->assertSame('upgrade', $setup['mode'] ?? null);
		$this->assertSame(getenv('UPGRADE_FROM'), $setup['from'] ?? null);
		$this->assertSame(1, $setup['delays'] ?? null, 'the seed delayed failed logins');
		$this->assertArrayNotHasKey('scenario', $setup);
		$this->assertArrayNotHasKey('disabled', $setup);
		$this->assertArrayNotHasKey('completed', $setup);
		// the quick icon and the console plugin are new in 2.0.0: installed, switched on
		foreach (array('quickicon', 'console') as $folder)
		{
			$this->assertSame(1, (int) $this->queryValue("SELECT enabled FROM #__extensions WHERE type='plugin' AND folder='".
				$folder."' AND element='bfstop'"), $folder);
		}
	}

	public function testUpdateMessages()
	{
		// the CLI wraps the messages
		$log = preg_replace('/\s+/', ' ', (string) file_get_contents(getenv('UPGRADE_LOG')));
		// what the update changed and what is left to decide is the setup
		// assistant's (it replaced the hints of the settings which moved and
		// of the API), with the console commands on the command line
		$this->assertSame(1, substr_count($log, 'Action required: open the setup assistant'), 'the message of the setup');
		$this->assertSame(1, substr_count($log, 'bfstop:setup --no-proxy'), 'the console commands');
		$this->assertSame(0, substr_count($log, 'major configuration changes'), 'the former hint of the settings which moved');
		$this->assertSame(0, substr_count($log, 'installed but not active yet'), 'the message of a new installation');
		// the seed delays failed logins by 90 seconds, which 2.0.0 doesn't any more
		$this->assertSame(1, substr_count($log, 'no longer delays the response to failed logins'),
			'the notice that the delays are gone');
	}

	public function testSettingsAreKeptAndMigrated()
	{
		// they are the component's params since 2.0.0, the plugin's before
		$this->assertSame(array(), json_decode((string) $this->queryValue(
			"SELECT params FROM #__extensions WHERE type='plugin' AND folder='system' AND element='bfstop'"), true) ?: array(),
			'the settings moved from the plugin to the component');
		// whose "Options" page would store its params with only the permissions
		$this->assertFileDoesNotExist(JPATH_ADMINISTRATOR.'/components/com_bfstop/config.xml');
		$params = json_decode($this->getSettings(), true);
		$this->assertSame('full', $params['blockMode'] ?? null, 'blockEnabled/useHtaccess became blockMode');
		$this->assertSame('15', (string) $params['blockNumber']);
		foreach (array('delayDuration', 'adaptiveDelay', 'adaptiveDelayMax', 'adaptiveDelayThresholdMin',
			'adaptiveDelayThresholdMax') as $removed)
		{
			$this->assertArrayNotHasKey($removed, $params, 'the delays are gone in 2.0.0');
		}
		$this->assertSame(version_compare(getenv('UPGRADE_FROM'), '2.0.0-dev', '<') ? 7 : 3,
			(int) $params['enabledForOrigin'], 'frontend and backend became frontend, backend and API (the seed is in 1.x form)');
	}

	public function testFailedLoginsAreIndexed()
	{
		$indexes = \Codeling\Bfstop\Tests\Integration\InstallTest::indexedColumns($this->db, 'bfstop_failedlogin');
		foreach (array('ipaddress,logtime', 'username,logtime', 'logtime') as $columns)
		{
			$this->assertContains($columns, $indexes);
		}
	}

	public function testTablesAreConverted()
	{
		$this->db->setQuery('SELECT TABLE_NAME, TABLE_COLLATION FROM information_schema.TABLES '.
			'WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE '.$this->db->quote($this->db->getPrefix().'bfstop%'));
		$collations = $this->db->loadAssocList('TABLE_NAME', 'TABLE_COLLATION');
		$this->assertCount(count(self::Tables), $collations);
		foreach ($collations as $table => $collation)
		{
			$this->assertStringStartsWith('utf8mb4', $collation, $table);
		}
		$this->db->setQuery('SELECT username, attempts FROM #__bfstop_username_stats ORDER BY attempts DESC, username');
		$stats = $this->db->loadAssocList('username', 'attempts');
		$this->assertCount(3, $stats, 'Bob and bob are one user name');
		$this->assertSame(array(2, 2, 1), array_map('intval', array_values($stats)));
	}

	public function testTheUpdateConvertsTheStoredAddresses()
	{
		// no request has done it: the update does (it was the first request's job until 2.0.0)
		$this->db->setQuery('SELECT ipaddress FROM #__bfstop_bannedip ORDER BY id');
		$this->assertSame(array('2001:db8::5', '203.0.113.0/24', '198.51.100.9'), $this->db->loadColumn());
		$this->assertSame('abcd::1', $this->queryValue('SELECT ipaddress FROM #__bfstop_allowlist'));
		$params = json_decode($this->getSettings(), true);
		$this->assertArrayNotHasKey('addressesCanonical', $params);
		$this->assertArrayNotHasKey('lastPurge', $params, 'the bookkeeping is not in the settings any more');
		$this->assertNotNull($this->queryValue("SELECT value FROM #__bfstop_state WHERE name='lastMaintenance'"));

		// and what was blocked stays blocked
		$this->assertStringContainsString('STATUS: 403', $this->request('2001:db8::5'));
		$this->assertStringContainsString('STATUS: 403', $this->request('203.0.113.99'));
		$this->assertStringContainsString('NOT BLOCKED', $this->request('192.0.2.201'));
	}

	public function testThePackageMadeTheMaintenanceTask()
	{
		// the task plugin is new in 2.0.0: the update installs it, switched on, with its task
		$this->assertSame(1, (int) $this->queryValue("SELECT COUNT(*) FROM #__scheduler_tasks WHERE type='bfstop.maintenance' AND state=1"));
		$this->assertSame(1, (int) $this->queryValue("SELECT enabled FROM #__extensions WHERE type='plugin' AND folder='task' AND element='bfstop'"));
	}

	public function testAnUpdateWhichStoppedHalfwayCanBeRepeated()
	{
		// the schema version stays at the previous one if the update SQL
		// stops; the next attempt runs it again on tables it already changed
		$this->db->setQuery("UPDATE #__schemas SET version_id='1.4.3' WHERE extension_id=".$this->pluginId());
		$this->db->execute();
		$this->assertSame(0, $this->install(getenv('BFSTOP_PACKAGE'), $output), $output);
		$this->assertSame(self::latestSchema(), $this->schemaVersion());
	}

	public function testPackageRefusesJoomlaVersionsItDoesNotSupport()
	{
		// the same package, except that it needs a Joomla version which
		// doesn't exist yet: the installation has to stop before it changes
		// anything
		// first the package as it is: its installation has to work now, so
		// that a failure below is the version check, not anything else
		$this->assertSame(0, $this->install(getenv('BFSTOP_PACKAGE'), $output), $output);
		$copy = sys_get_temp_dir().'/bfstop-upgrade-test-'.getmypid().'.zip';
		copy(getenv('BFSTOP_PACKAGE'), $copy);
		try
		{
			$zip = new \ZipArchive();
			$this->assertTrue($zip->open($copy));
			$script = $zip->getFromName('script.php');
			$this->assertMatchesRegularExpression('/\$minimumJoomla = \'[0-9.]+\'/', $script);
			$zip->addFromString('script.php', preg_replace('/\$minimumJoomla = \'[0-9.]+\'/', "\$minimumJoomla = '99.0.0'", $script));
			$zip->close();

			$before = $this->installedVersions();
			$this->assertNotSame(0, $this->install($copy, $output), $output);
			$this->assertSame($before, $this->installedVersions());
		}
		finally
		{
			@unlink($copy);
		}
	}
}
