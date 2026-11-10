<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Extension\Bfstop;
use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
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
	private $createdUsers = array();
	// the site's $live_site in the requests of the failed logins: unblock
	// links for any address are only sent with it
	private $liveSite = 'https://www.example.org';

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
		$db->setQuery("SELECT params FROM #__extensions WHERE type='plugin' AND element='bfstop'");
		self::$originalParams = $db->loadResult();
	}

	public static function tearDownAfterClass(): void
	{
		if (self::$originalParams !== null)
		{
			$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
			$db->setQuery('UPDATE #__extensions SET params='.$db->quote(self::$originalParams).
				" WHERE type='plugin' AND element='bfstop'");
			$db->execute();
		}
	}

	protected function tearDown(): void
	{
		foreach ($this->createdUsers as $id)
		{
			$this->db->setQuery('DELETE FROM #__users WHERE id='.(int) $id);
			$this->db->execute();
		}
	}

	private function createUser($username)
	{
		$id = $this->insert('#__users', array('name' => $username, 'username' => $username,
			'email' => $username.'@example.org', 'password' => '', 'registerDate' => self::minutesAgo(0),
			'params' => '{}'), 'id');
		$this->createdUsers[] = $id;
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

	/**
	 * @param string[] $options further options of fixtures/failed_login.php
	 *                          (--api, --server=...)
	 */
	private function command($username, $ip = self::Ip, array $options = array())
	{
		return escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/fixtures/failed_login.php').' '.
			escapeshellarg($ip).' '.escapeshellarg($username).
			implode('', array_map(function ($option) { return ' '.escapeshellarg($option); }, $options));
	}

	private function failedLogin($username, $ip = self::Ip, array $options = array())
	{
		if ($this->liveSite !== '')
		{
			$options[] = '--live-site='.$this->liveSite;
		}
		exec($this->command($username, $ip, $options).' 2>&1', $output, $exitCode);
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

	/**
	 * A failed login to the Web Services API: Joomla reports it with an empty
	 * username whatever the request carried. $headers as in $_SERVER
	 */
	private function failedApiLogin(array $headers = array(), $ip = self::Ip)
	{
		$options = array('--api');
		foreach ($headers as $name => $value)
		{
			$options[] = '--server='.$name.'='.$value;
		}
		$this->failedLogin('', $ip, $options);
	}

	public function testApiLoginsWithoutCredentialsAreNotCounted()
	{
		// Joomla tries to log in every request to an endpoint which isn't
		// public, also those which carry no credentials at all
		$this->configure(array('blockNumber' => 2));
		$this->failedApiLogin();
		$this->failedApiLogin();
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'));
		$this->assertFalse((new DatabaseHelper($this->logger))->isIPBlocked(self::Ip));
	}

	public function testApiLoginsWithCredentialsAreCountedAndBlocked()
	{
		$this->configure(array('blockNumber' => 3, 'unknownUsernameMode' => 'plain'));
		$this->failedApiLogin(array('PHP_AUTH_USER' => 'bob', 'PHP_AUTH_PW' => 'guess'));
		$this->failedApiLogin(array('HTTP_AUTHORIZATION' => 'Basic '.base64_encode('carol:guess')));
		$this->failedApiLogin(array('HTTP_AUTHORIZATION' => 'Bearer c2hhMjU2OjQyOmFiYw=='));
		// HTTP Basic gives the username; a token names its user by id only
		$this->assertSame(array('bob', 'carol', ''), $this->storedUsernames());
		$this->assertSame(array('3', '3', '3'), array_map('strval',
			$this->db->setQuery('SELECT origin FROM #__bfstop_failedlogin ORDER BY id')->loadColumn()));
		$this->assertTrue((new DatabaseHelper($this->logger))->isIPBlocked(self::Ip));
	}

	public function testApiLoginsAreOnlyCountedIfSwitchedOn()
	{
		$this->configure(array('enabledForOrigin' => Bfstop::OriginFrontend | Bfstop::OriginBackend));
		$this->failedApiLogin(array('HTTP_X_JOOMLA_TOKEN' => 'c2hhMjU2OjQyOmFiYw=='));
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'));
		$this->failedLogin('bob');
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'));
	}

	public function testTrustedProxyIsNotBlockedThroughHtaccess()
	{
		// a failed login through a trusted proxy without the header naming
		// the client is counted against the proxy (not counting it would let
		// such requests fail logins without limit) - but in .htaccess, the
		// proxy's address would turn away every visitor coming through it
		$dir = sys_get_temp_dir().'/bfstop-proxy-htaccess-'.getmypid();
		mkdir($dir);
		try
		{
			$this->configure(array('blockNumber' => 2, 'blockMode' => 'htaccess', 'htaccessPath' => $dir,
				'useProxy' => 1, 'proxyIpAddress' => self::Ip));
			$this->failedLogin('Admin');
			$this->failedLogin('Admin');
			$this->assertSame(self::Ip, $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'), 'blocked in the database');
			$this->assertStringNotContainsString(self::Ip, (string) @file_get_contents($dir.'/.htaccess'));

			// a client the proxy names in the header is blocked through .htaccess
			$header = array('--server=HTTP_X_FORWARDED_FOR=203.0.113.99');
			$this->failedLogin('Admin', self::Ip, $header);
			$this->failedLogin('Admin', self::Ip, $header);
			$this->assertStringContainsString("-R '203.0.113.99'", (string) file_get_contents($dir.'/.htaccess'));
		}
		finally
		{
			@unlink($dir.'/.htaccess');
			@rmdir($dir);
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

	public function testAccountThrottleDoesNotDelayABlockedAddress()
	{
		// the account has been attacked from elsewhere: every further failed
		// login for it would be delayed, but this one got its address blocked
		$this->configure(array('blockNumber' => 1, 'accountThrottleEnabled' => 1, 'accountBlockNumber' => 2,
			'accountThrottleDelay' => 5));
		foreach (array('203.0.113.60', '203.0.113.61', '203.0.113.62') as $ip)
		{
			$this->insert('#__bfstop_failedlogin', array('username' => 'Admin', 'ipaddress' => $ip,
				'logtime' => self::minutesAgo(1), 'origin' => 0, 'handled' => 0));
		}
		$start = microtime(true);
		$this->failedLogin('Admin');
		$this->assertLessThan(4.0, microtime(true) - $start);
		$this->assertSame(self::Ip, $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));
	}

	public function testOnlySoManyResponsesAreDelayedAtTheSameTime()
	{
		// every delayed response holds a PHP worker: with all slots taken
		// (here by this test), the response goes out at once - and the
		// failed login counts all the same
		$this->configure(array('blockNumber' => 2, 'delayDuration' => 5, 'delayMaxConcurrent' => 2));
		$handles = array();
		try
		{
			foreach (Bfstop::delaySlotFiles(2) as $file)
			{
				$handle = fopen($file, 'c');
				// waits for a delayed response of an earlier test which still
				// runs (proc_terminate() only ends the shell around it)
				$this->assertTrue(flock($handle, LOCK_EX), $file);
				$handles[] = $handle;
			}
			$start = microtime(true);
			$this->failedLogin('Admin');
			$this->assertLessThan(3.0, microtime(true) - $start, 'not delayed');
			$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'));
			$this->failedLogin('Admin');
			$this->assertSame(self::Ip, $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'), 'blocked as usual');

			// one slot free again: delayed
			flock(array_pop($handles), LOCK_UN);
			$start = microtime(true);
			$this->failedLogin('Admin', '203.0.113.52');
			$this->assertGreaterThanOrEqual(4.5, microtime(true) - $start, 'delayed');
		}
		finally
		{
			foreach ($handles as $handle)
			{
				flock($handle, LOCK_UN);
				fclose($handle);
			}
		}
	}

	public function testRiskScoreAddsNoDelayByDefault()
	{
		$this->assertSame(0, Bfstop::DefaultSettings['riskDelaySecondsPerPoint']);
		// "admin" is a common username, and there is no User-Agent: 4 points
		$this->setPluginParams(json_encode(array('blockMode' => 'full', 'accountThrottleEnabled' => 0)));
		$start = microtime(true);
		$this->failedLogin('admin', self::Ip, array('--server=HTTP_USER_AGENT='));
		$this->assertLessThan(3.0, microtime(true) - $start);
	}

	public function testDelaysAreCapped()
	{
		$this->assertSame(0, Bfstop::cappedDelay(0));
		$this->assertSame(0, Bfstop::cappedDelay(-5));
		$this->assertSame(7, Bfstop::cappedDelay(6.6));
		$this->assertSame(Bfstop::MaxDelaySeconds, Bfstop::cappedDelay(100000));
	}

	public function testExistingAndCommonUsernamesAreStoredReadably()
	{
		$this->configure();
		$this->failedLogin('Admin');
		$this->failedLogin('admin'); // as typed
		$this->failedLogin('ROOT');
		$this->assertSame(array('Admin', 'admin', 'ROOT'), $this->storedUsernames());
		// MySQL's collation is case-insensitive, so "Admin" and "admin" share a
		// row there, PostgreSQL's isn't: what has to hold on both is that every
		// attempt is counted
		$this->assertSame(3, (int) $this->queryValue('SELECT SUM(attempts) FROM #__bfstop_username_stats'));
		$this->assertSame(1, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_username_stats WHERE username = 'ROOT'"));
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

	private function requestFrom($ip)
	{
		$command = escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/fixtures/request.php').' '.escapeshellarg($ip).' 2>&1';
		exec($command, $output, $exitCode);
		$this->assertSame(0, $exitCode, implode("\n", $output));
		return implode("\n", $output);
	}

	public function testIpv6ClientsAreTrackedAndBlockedByNetwork()
	{
		// switching to another address in its /56 - also in another of its
		// /64s - must not reset an attacker (the default granularity)
		$this->configure(array('blockNumber' => 3, 'blockedMessage' => 'BFSTOP TEST: blocked'));
		$this->failedLogin('Admin', '2001:db8:1:2::1');
		$this->failedLogin('Admin', '2001:db8:1:5a:aaaa::2');
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
		$this->failedLogin('Admin', '2001:db8:1:ff:bbbb::3');

		$this->assertSame('2001:db8:1::/56', $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
		$this->assertStringContainsString('BFSTOP TEST: blocked', $this->requestFrom('2001:db8:1:7:cccc::4'));
		$this->assertStringContainsString('NOT BLOCKED', $this->requestFrom('2001:db8:1:100::1'), 'a different /56');
		$this->assertStringContainsString('NOT BLOCKED', $this->requestFrom('203.0.113.7'));
	}

	public function testIpv6NetworksCanBeTrackedPer64()
	{
		$this->configure(array('blockNumber' => 2, 'ipv6PrefixLength' => 64));
		$this->failedLogin('Admin', '2001:db8:1:2::1');
		$this->failedLogin('Admin', '2001:db8:1:3::1');
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
		$this->failedLogin('Admin', '2001:db8:1:2:aaaa::2');
		$this->assertSame('2001:db8:1:2::/64', $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));
	}

	public function testBlockedNetworkIsNotBlockedAgain()
	{
		$this->configure(array('blockNumber' => 1));
		$this->failedLogin('Admin', '2001:db8:1:2::1');
		$this->failedLogin('Admin', '2001:db8:1:2::2'); // its network is blocked already
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
	}

	public function testIpv6PrefixCanBeSwitchedOff()
	{
		$this->configure(array('blockNumber' => 2, 'ipv6PrefixLength' => 128));
		$this->failedLogin('Admin', '2001:db8:1:2::1');
		$this->failedLogin('Admin', '2001:db8:1:2::2');
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
		$this->failedLogin('Admin', '2001:db8:1:2::2');
		$this->assertSame('2001:db8:1:2::2', $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));
	}

	public function testIpv4MappedAddressesAreNotLumpedTogether()
	{
		$this->configure(array('blockNumber' => 2));
		$this->failedLogin('Admin', '::ffff:203.0.113.7');
		$this->failedLogin('Admin', '::ffff:203.0.113.8');
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
	}

	// The unblock token is created when the email with the link is prepared,
	// so whether a token exists tells whether the link would be sent.
	private function unblockLinkIssued()
	{
		return ((int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock_token')) === 1;
	}

	private function blockedAfter(array $usernames)
	{
		$this->configure(array('blockNumber' => count($usernames), 'notifyBlockedUser' => 2));
		foreach ($usernames as $username)
		{
			$this->failedLogin($username);
		}
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'), 'blocked');
	}

	public function testUnblockLinkIsIssuedIfOnlyThatAccountWasTargeted()
	{
		$this->blockedAfter(array('Admin', 'Admin', 'Admin'));
		$this->assertTrue($this->unblockLinkIssued());
	}

	public function testNoUnblockLinkIfAnotherAccountWasTargeted()
	{
		// the link goes to whoever owns the account of the last attempt: an
		// attacker who owns one account mustn't get unblocked after going
		// after other accounts from the same address
		$this->createUser('victim');
		$this->blockedAfter(array('victim', 'victim', 'Admin'));
		$this->assertFalse($this->unblockLinkIssued());
	}

	public function testNoUnblockLinkIfAnotherAccountWasTargetedByEmailAddress()
	{
		$this->createUser('victim');
		$this->blockedAfter(array('victim@example.org', 'victim@example.org', 'Admin'));
		$this->assertFalse($this->unblockLinkIssued());
	}

	public function testMistypedUsernamesDontPreventTheUnblockLink()
	{
		// attempts against names which aren't an account harm nobody
		$this->blockedAfter(array('adm1n', 'Admn', 'Admin'));
		$this->assertTrue($this->unblockLinkIssued());
	}

	public function testMistypedUsernamesInPlainModeDontPreventTheUnblockLink()
	{
		$this->configure(array('blockNumber' => 3, 'notifyBlockedUser' => 2, 'unknownUsernameMode' => 'plain'));
		foreach (array('nobody', 'nobody-else', 'Admin') as $username)
		{
			$this->failedLogin($username);
		}
		$this->assertTrue($this->unblockLinkIssued());
	}

	public function testOtherSpellingOfTheSameAccountIsTheSameAccount()
	{
		$this->blockedAfter(array('admin', 'ADMIN', 'Admin'));
		$this->assertTrue($this->unblockLinkIssued());
	}

	public function testOnlyAttemptsOfTheSameAddressCount()
	{
		$this->createUser('victim');
		$this->configure(array('blockNumber' => 2, 'notifyBlockedUser' => 2));
		$this->failedLogin('victim', '203.0.113.99'); // somebody else
		$this->failedLogin('Admin');
		$this->failedLogin('Admin');
		$this->assertSame(self::Ip, $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));
		$this->assertTrue($this->unblockLinkIssued());
	}

	private function knownIp($ip, $username)
	{
		$this->insert('#__bfstop_knownip', array('ipaddress' => $ip, 'username' => $username,
			'first_success' => self::minutesAgo(100), 'last_success' => self::minutesAgo(10)));
	}

	private function tokenCount($where = '1=1')
	{
		return (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock_token WHERE '.$where);
	}

	private function blockWith($mode, $username = 'Admin', $ip = self::Ip)
	{
		$this->configure(array('blockNumber' => 3, 'notifyBlockedUser' => $mode));
		for ($i = 0; $i < 3; ++$i)
		{
			$this->failedLogin($username, $ip);
		}
	}

	public function testNoUnblockLinkIfSwitchedOff()
	{
		$this->blockWith(0);
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
		$this->assertSame(0, $this->tokenCount());
	}

	// mode 1: only for IP addresses the user has logged in from

	public function testKnownAddressModeSendsLinkIfTheUserLoggedInFromThere()
	{
		$this->knownIp(self::Ip, 'Admin');
		$this->blockWith(1);
		$this->assertSame(1, $this->tokenCount("username = 'Admin'"));
	}

	public function testKnownAddressModeNeverSendsToAnAttackersAddress()
	{
		// nobody ever logged in as Admin from here
		$this->blockWith(1);
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
		$this->assertSame(0, $this->tokenCount());
	}

	public function testKnownAddressModeIgnoresLoginsOfOtherUsersAndAddresses()
	{
		$this->knownIp(self::Ip, 'someone-else');
		$this->knownIp('203.0.113.77', 'Admin');
		$this->blockWith(1);
		$this->assertSame(0, $this->tokenCount());
	}

	public function testKnownAddressModeIsCaseInsensitiveForTheUsername()
	{
		$this->knownIp(self::Ip, 'admin');
		$this->blockWith(1);
		$this->assertSame(1, $this->tokenCount());
	}

	public function testKnownAddressModeRecognisesTheNetworkOfAnIpv6Client()
	{
		// IPv6 clients switch to other addresses in their network all the time
		$this->knownIp('2001:db8:1:f0:aaaa:bbbb:cccc:9', 'Admin');
		$this->blockWith(1, 'Admin', '2001:db8:1:2::1');
		$this->assertSame(1, $this->tokenCount());
	}

	public function testKnownAddressModeDoesntRecogniseAnotherIpv6Network()
	{
		$this->knownIp('2001:db8:1:300:aaaa::9', 'Admin');
		$this->blockWith(1, 'Admin', '2001:db8:1:2::1');
		$this->assertSame(0, $this->tokenCount());
	}

	public function testKnownAddressModeDoesntLumpIpv4MappedAddressesTogether()
	{
		$this->knownIp('::ffff:203.0.113.8', 'Admin');
		$this->blockWith(1, 'Admin', '::ffff:203.0.113.7');
		$this->assertSame(0, $this->tokenCount());
	}

	// mode 2: any address, but only one usable link per user

	public function testAnyAddressModeSendsOnlyOneUsableLinkAtATime()
	{
		$this->blockWith(2);
		$this->assertSame(1, $this->tokenCount("username = 'Admin'"));
		// the same user, from another address (another botnet member)
		$this->blockWith(2, 'Admin', '203.0.113.52');
		$this->assertSame(2, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'), 'blocked');
		$this->assertSame(1, $this->tokenCount(), 'no second link');
	}

	public function testAnyAddressModeSendsAnotherLinkOnceTheOldOneExpired()
	{
		$this->insert('#__bfstop_unblock_token', array('token' => str_repeat('ab', 20), 'block_id' => 1,
			'crdate' => self::minutesAgo(4 * 24 * 60), 'username' => 'Admin'));
		$this->blockWith(2);
		$this->assertSame(2, $this->tokenCount("username = 'Admin'"));
	}

	public function testAnyAddressModeSendsAnotherLinkOnceTheOldOneWasUsed()
	{
		// a token which was used up is deleted, so there is none left
		$this->blockWith(2);
		$this->db->setQuery('DELETE FROM #__bfstop_unblock_token');
		$this->db->execute();
		$this->blockWith(2, 'Admin', '203.0.113.52');
		$this->assertSame(1, $this->tokenCount("username = 'Admin'"));
	}

	public function testAnyAddressModeLimitsPerUser()
	{
		$this->createUser('victim');
		$this->insert('#__bfstop_unblock_token', array('token' => str_repeat('cd', 20), 'block_id' => 1,
			'crdate' => self::minutesAgo(10), 'username' => 'victim'));
		$this->blockWith(2);
		$this->assertSame(1, $this->tokenCount("username = 'Admin'"), 'the link for victim has no bearing on Admin');
	}

	// without the site's $live_site, the link has the host the request of the
	// attacker's failed login named: links for any address (mode 2) are then
	// only sent where mode 1 would send them

	public function testAnyAddressModeWithoutLiveSiteNeverSendsToAnAttackersAddress()
	{
		$this->liveSite = '';
		$this->blockWith(2);
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'), 'blocked');
		$this->assertSame(0, $this->tokenCount());
	}

	public function testAnyAddressModeWithoutLiveSiteSendsLinkIfTheUserLoggedInFromThere()
	{
		$this->liveSite = '';
		$this->knownIp(self::Ip, 'Admin');
		$this->blockWith(2);
		$this->assertSame(1, $this->tokenCount("username = 'Admin'"));
	}

	public function testEffectiveNotifyBlockedUserSetting()
	{
		foreach (array(0, 1, 2) as $setting)
		{
			$this->assertSame($setting, Bfstop::effectiveNotifyBlockedUser((string) $setting, true));
		}
		$this->assertSame(0, Bfstop::effectiveNotifyBlockedUser(0, false));
		$this->assertSame(1, Bfstop::effectiveNotifyBlockedUser(1, false));
		$this->assertSame(1, Bfstop::effectiveNotifyBlockedUser('2', false));
	}
}
