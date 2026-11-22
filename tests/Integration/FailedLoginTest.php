<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Origin;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\BlockPolicy;
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
		$db->setQuery("SELECT params FROM #__extensions WHERE type='component' AND element='com_bfstop'");
		self::$originalParams = $db->loadResult();
	}

	public static function tearDownAfterClass(): void
	{
		if (self::$originalParams !== null)
		{
			$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
			self::storeSettings($db, self::$originalParams);
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
		$this->setSettings(json_encode($params + array(
			'blockMode' => 'full',
			'blockNumber' => 15,
			'riskMinBlockNumber' => 1,
			'riskBlockNumberReductionPerPoint' => 0,
			'checkInterval' => 60,
			'blockDuration' => 60,
			'accountAttackEnabled' => 0,
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

	public function testAnAccountUnderAttackGetsItsAttackersBlockedSooner()
	{
		// the failed logins of other addresses on the account count for every
		// address which tries it: blocked after 5 - 3 points = 2 attempts
		$this->configure(array('blockNumber' => 5, 'riskBlockNumberReductionPerPoint' => 1,
			'riskUserAgentEnabled' => 0, 'riskCommonUsernameEnabled' => 0, 'riskKnownIpEnabled' => 0,
			'accountAttackEnabled' => 1, 'accountBlockNumber' => 3, 'accountAttackPoints' => 3));
		$this->failedLogin('Admin', '203.0.113.60');
		// as stored: readable, or the hash of a username which is no account
		$stored = $this->storedUsernames()[0];
		$this->insert('#__bfstop_failedlogin', array('username' => $stored, 'ipaddress' => '203.0.113.61',
			'logtime' => self::minutesAgo(1), 'origin' => 0, 'handled' => 0));
		$this->failedLogin('Admin');
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'), '3 of 3, 2 allowed');
		$this->failedLogin('Admin');
		$this->assertSame(self::Ip, $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));

		// another account, not attacked: the usual 5 attempts
		$this->failedLogin('Bob', '203.0.113.70');
		$this->failedLogin('Bob', '203.0.113.70');
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
	}

	public function testAFailedLoginIsAnsweredAtOnce()
	{
		// nothing holds the response back (and a PHP worker with it), not
		// even with the account under attack and a risky request
		$this->configure(array('blockNumber' => 100, 'riskBlockNumberReductionPerPoint' => 1,
			'accountAttackEnabled' => 1, 'accountBlockNumber' => 1));
		$start = microtime(true);
		$this->failedLogin('admin', self::Ip, array('--server=HTTP_USER_AGENT='));
		$this->assertLessThan(3.0, microtime(true) - $start);
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'));
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

	private function blockedAfter(array $usernames, array $params = array())
	{
		$this->configure($params + array('blockNumber' => count($usernames), 'notifyBlockedUser' => 2));
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

	public function testUnblockLinkForALoginTypedWithTheEmailAddressOrInAnotherCase()
	{
		// accountExists() takes these for the account, so does the unblock mail
		$this->createUser('victim');
		$this->blockedAfter(array('Victim@Example.org', 'Victim@Example.org', 'Victim@Example.org'));
		$this->assertTrue($this->unblockLinkIssued());
		$this->assertSame('victim', $this->queryValue('SELECT username FROM #__bfstop_unblock_token'),
			'the link is counted against the account');
	}

	public function testNoUnblockLinkForADisabledAccount()
	{
		$this->createUser('disabled');
		$this->db->setQuery("UPDATE #__users SET block=1 WHERE username='disabled'");
		$this->db->execute();
		$this->blockedAfter(array('disabled', 'disabled', 'disabled'));
		$this->assertFalse($this->unblockLinkIssued());
	}

	public function testNoUnblockMailIfItsTokenCannotBeStored()
	{
		// a link whose token isn't stored leads nowhere: it used to be sent
		// with an empty token
		$logFile = \Codeling\Library\Bfstop\Helper\LoggerHelper::getLogFiles()[0];
		@unlink($logFile);
		// lookups of the table still work, adding a token fails
		$table = $this->db->quoteName('#__bfstop_unblock_token');
		$this->db->setQuery('ALTER TABLE '.$table.' ADD CONSTRAINT bfstop_test_no_token CHECK (block_id < 0)');
		$this->db->execute();
		try
		{
			$this->blockedAfter(array('Admin', 'Admin', 'Admin'), array('logLevel' => 64)); // Log::INFO
		}
		finally
		{
			$this->db->setQuery('ALTER TABLE '.$table.' DROP CONSTRAINT bfstop_test_no_token');
			$this->db->execute();
		}
		$this->assertFalse($this->unblockLinkIssued());
		$log = (string) @file_get_contents($logFile);
		$this->assertStringContainsString('unblock token could not be stored - not sending unblock instructions', $log);
		$this->assertStringNotContainsString('sending unblock instructions', str_replace(
			'not sending unblock instructions', '', $log));
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
		$this->knownIp('2001:db8:1:2:aaaa:bbbb:cccc:9', 'Admin');
		$this->blockWith(1, 'Admin', '2001:db8:1:2::1');
		$this->assertSame(1, $this->tokenCount());
	}

	public function testKnownAddressModeDoesntTrustTheRestOfTheFailedLoginNetwork()
	{
		// failed logins are counted per /56, but the next /64 may be another customer's
		$this->knownIp('2001:db8:1:f0:aaaa:bbbb:cccc:9', 'Admin');
		$this->blockWith(1, 'Admin', '2001:db8:1:2::1');
		$this->assertSame(0, $this->tokenCount());
	}

	public function testKnownAddressModeIgnoresLoginsRememberedForALargeNetwork()
	{
		// what versions before this one remembered an IPv6 login as
		$this->knownIp('2001:db8:1::/56', 'Admin');
		$this->blockWith(1, 'Admin', '2001:db8:1:2::1');
		$this->assertSame(0, $this->tokenCount());
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
	// failed login named, which whoever sends it picks: no link is sent then,
	// also not to a user who logged in from the address (others may share it)

	public function testAnyAddressModeWithoutLiveSiteNeverSendsToAnAttackersAddress()
	{
		$this->liveSite = '';
		$this->blockWith(2);
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'), 'blocked');
		$this->assertSame(0, $this->tokenCount());
	}

	public function testNoUnblockLinkWithoutLiveSiteEvenIfTheUserLoggedInFromThere()
	{
		$this->liveSite = '';
		foreach (array(1, 2) as $mode)
		{
			$this->emptyTables();
			$this->knownIp(self::Ip, 'Admin');
			$this->blockWith($mode);
			$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'), "mode $mode: blocked");
			$this->assertSame(0, $this->tokenCount(), "mode $mode");
		}
	}

	public function testEffectiveNotifyBlockedUserSetting()
	{
		foreach (array(0, 1, 2) as $setting)
		{
			$this->assertSame($setting, BlockPolicy::effectiveNotifyBlockedUser((string) $setting, true));
		}
		$this->assertSame(0, BlockPolicy::effectiveNotifyBlockedUser(0, false));
		$this->assertSame(0, BlockPolicy::effectiveNotifyBlockedUser(1, false));
		$this->assertSame(0, BlockPolicy::effectiveNotifyBlockedUser('2', false));
	}
}
