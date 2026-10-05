<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Joomla\CMS\Factory;

/**
 * How the plugin handles a failed login, with the settings it reads from the
 * database: each failed login runs in a separate process (see
 * fixtures/failed_login.php), as it would in a real request.
 */
class FailedLoginTest extends IntegrationTestCase
{
	private const Ip = '203.0.113.51';

	private static $originalParams;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		$db = Factory::getDbo();
		$db->setQuery("SELECT params FROM #__extensions WHERE type='plugin' AND element='bfstop'");
		self::$originalParams = $db->loadResult();
	}

	public static function tearDownAfterClass(): void
	{
		if (self::$originalParams !== null)
		{
			$db = Factory::getDbo();
			$db->setQuery('UPDATE #__extensions SET params='.$db->quote(self::$originalParams).
				" WHERE type='plugin' AND element='bfstop'");
			$db->execute();
		}
	}

	private function configure(array $params = array())
	{
		$this->setPluginParams(json_encode($params + array(
			'blockMode' => 'full',
			'blockNumber' => 15,
			'riskMinBlockNumber' => 1,
			'riskBlockNumberReductionPerPoint' => 0,
			'riskDelaySecondsPerPoint' => 0,
			'checkInterval' => 60,
			'blockDuration' => 60,
			'delayDuration' => 0,
			'accountThrottleEnabled' => 0,
			'notifyBlockedNumber' => 0,
			'riskCommonUsernames' => "root\nadministrator",
			'logLevel' => 8, // errors only
		)));
	}

	private function command($username, $ip = self::Ip)
	{
		return escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/fixtures/failed_login.php').' '.
			escapeshellarg($ip).' '.escapeshellarg($username);
	}

	private function failedLogin($username, $ip = self::Ip)
	{
		exec($this->command($username, $ip).' 2>&1', $output, $exitCode);
		$output = implode("\n", $output);
		$this->assertSame(0, $exitCode, $output);
		$this->assertStringContainsString('DONE', $output);
	}

	private function storedUsernames()
	{
		$this->db->setQuery('SELECT username FROM #__bfstop_failedlogin ORDER BY id');
		return $this->db->loadColumn();
	}

	public function testFailedLoginIsRecordedBeforeTheDelay()
	{
		// the delay only holds back the response; the attempt has to count
		// right away, or a burst of parallel requests all start before the
		// first one reaches the block threshold
		$this->configure(array('delayDuration' => 5));
		$process = proc_open($this->command('Admin'),
			array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes);
		$this->assertIsResource($process);
		try
		{
			$recorded = false;
			for ($i = 0; $i < 40 && !$recorded; ++$i)
			{
				usleep(100000);
				$recorded = ((int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin')) === 1;
			}
			$this->assertTrue($recorded, 'failed login was not recorded within 4s (the delay is 5s)');
			$this->assertTrue(proc_get_status($process)['running'],
				'the request should still be delayed at this point');
		}
		finally
		{
			proc_terminate($process);
			proc_close($process);
		}
	}

	public function testBlockedAddressIsNotDelayed()
	{
		$this->configure(array('delayDuration' => 5, 'blockNumber' => 1));
		$start = microtime(true);
		$this->failedLogin('Admin');
		$this->assertLessThan(4.0, microtime(true) - $start, 'a request that got its address blocked must not wait for the delay');
		$this->assertSame(self::Ip, $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));
	}

	public function testExistingAndCommonUsernamesAreStoredReadably()
	{
		$this->configure();
		$this->failedLogin('Admin');
		$this->failedLogin('admin'); // as typed
		$this->failedLogin('ROOT');
		$this->assertSame(array('Admin', 'admin', 'ROOT'), $this->storedUsernames());
		$this->assertSame(3, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_username_stats'));
	}

	public function testOtherUsernamesAreStoredHashed()
	{
		// e.g. a password typed into the username field
		$this->configure();
		$this->failedLogin('hunter2-S3cret!');
		$this->failedLogin('HUNTER2-s3cret!');
		$this->failedLogin('another-one');
		$stored = $this->storedUsernames();
		foreach ($stored as $username)
		{
			$this->assertMatchesRegularExpression('/^\[unknown:[0-9a-f]{16}\]$/', $username);
		}
		$this->assertSame($stored[0], $stored[1], 'the same input has to give the same value, to count attempts together');
		$this->assertNotSame($stored[0], $stored[2]);
		$this->assertSame(2, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_username_stats'));
		$this->assertSame(2, (int) $this->queryValue('SELECT attempts FROM #__bfstop_username_stats WHERE username='.
			$this->db->quote($stored[0])));
		$this->assertSame(0, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_username_stats WHERE username LIKE '%hunter%'"));
	}

	public function testPlainModeStoresEveryUsername()
	{
		$this->configure(array('unknownUsernameMode' => 'plain'));
		$this->failedLogin('someone-unknown');
		$this->assertSame(array('someone-unknown'), $this->storedUsernames());
	}
}
