<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Joomla\Registry\Registry;

/**
 * Runs every query of DatabaseHelper against the actual database.
 */
class DatabaseHelperTest extends IntegrationTestCase
{
	private $helper;

	protected function setUp(): void
	{
		parent::setUp();
		$this->helper = new DatabaseHelper($this->logger);
	}

	private function failedLogin($ip, $username, $minutesAgo, $origin = 0)
	{
		$this->helper->insertFailedLogin((object) array('ipaddress' => $ip,
			'logtime' => self::minutesAgo($minutesAgo), 'username' => $username, 'origin' => $origin));
	}

	private function block($ip, $minutesAgo, $duration)
	{
		return $this->insert('#__bfstop_bannedip', array('ipaddress' => $ip,
			'crdate' => self::minutesAgo($minutesAgo), 'duration' => $duration), 'id');
	}

	private function activeBlocks($ip)
	{
		$ids = $this->helper->getActiveBlockIds($ip);
		sort($ids);
		return $ids;
	}

	public function testFailedLoginCounting()
	{
		$now = self::minutesAgo(0);
		foreach (array(0, 5, 30, 120) as $minutesAgo)
		{
			$this->failedLogin('203.0.113.5', 'bob', $minutesAgo);
		}
		$this->failedLogin('203.0.113.99', 'bob', 1, 1);
		$this->failedLogin('203.0.113.5', 'eve', 8 * 24 * 60);

		$this->assertSame(3, $this->helper->getNumberOfFailedLogins(60, '203.0.113.5', $now));
		$this->assertSame(4, $this->helper->getNumberOfFailedLogins(180, '203.0.113.5', $now));
		$this->assertSame(4, $this->helper->getNumberOfFailedLoginsForUsername(60, 'bob', $now));
		$this->assertSame(4, (int) $this->helper->getFailedLoginsInLastHour());
		$list = $this->helper->getFormattedFailedList('203.0.113.5', $now, 60);
		$this->assertSame(3 + 2, substr_count($list, "\n"), "2 header lines + 3 entries:\n".$list);

		$this->helper->setFailedLoginHandled((object) array('ipaddress' => '203.0.113.5', 'username' => 'bob'), true);
		$this->assertSame(0, $this->helper->getNumberOfFailedLogins(60, '203.0.113.5', $now));
		$this->assertSame(1, $this->helper->getNumberOfFailedLoginsForUsername(60, 'bob', $now), 'other IP not handled');
	}

	public function testUsernameStatistics()
	{
		// the log times are taken from the clock while inserting: compare against the window of
		// the inserts, as a second-exact value breaks when a second boundary passes before the assert
		$before = time();
		$this->failedLogin('203.0.113.5', 'bob', 30);
		$this->failedLogin('203.0.113.6', 'bob', 20);
		$this->failedLogin('203.0.113.5', 'bob', 10);
		$this->failedLogin('203.0.113.5', 'eve', 5);
		$after = time();

		$this->db->setQuery('SELECT username, attempts, first_attempt, last_attempt FROM #__bfstop_username_stats ORDER BY username');
		$rows = $this->db->loadObjectList();
		$this->assertCount(2, $rows);
		$this->assertSame(array('bob', 3), array($rows[0]->username, (int) $rows[0]->attempts));
		$this->assertGreaterThanOrEqual($before - 30 * 60, strtotime($rows[0]->first_attempt));
		$this->assertLessThanOrEqual($after - 30 * 60, strtotime($rows[0]->first_attempt));
		$this->assertGreaterThanOrEqual($before - 10 * 60, strtotime($rows[0]->last_attempt));
		$this->assertLessThanOrEqual($after - 10 * 60, strtotime($rows[0]->last_attempt));
		$this->assertSame(array('eve', 1), array($rows[1]->username, (int) $rows[1]->attempts));

		// not removed by the automatic purge, unlike the failed logins themselves
		$this->insert('#__bfstop_username_stats', array('username' => 'old', 'attempts' => 7,
			'first_attempt' => self::minutesAgo(90 * 24 * 60), 'last_attempt' => self::minutesAgo(80 * 24 * 60)));
		$this->helper->purgeOldEntries(1);
		$this->assertSame(3, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_username_stats'));
	}

	public function testActiveBlocks()
	{
		$exact = $this->block('203.0.113.5', 0, 60);
		$this->block('203.0.113.6', 120, 60); // expired
		$unlimited = $this->block('203.0.113.7', 500000, 0);
		$net4 = $this->block('198.51.100.0/24', 0, 0);
		$net4small = $this->block('203.0.113.4/31', 0, 0);
		$net6 = $this->block('2001:DB8:AB::/48', 0, 60);
		$exact6 = $this->block('2001:DB8::9', 0, 60);
		$this->block('192.0.2.0/99', 0, 0); // corrupted prefix lengths
		$this->block('192.0.2.0/abc', 0, 0);
		$unblocked = $this->block('203.0.113.8', 0, 0);
		$this->insert('#__bfstop_unblock', array('block_id' => $unblocked, 'source' => 0, 'crdate' => self::minutesAgo(0)));

		$this->assertSame(array($exact, $net4small), $this->activeBlocks('203.0.113.5'));
		$this->assertSame(array(), $this->activeBlocks('203.0.113.6'), 'expired');
		$this->assertSame(array($unlimited), $this->activeBlocks('203.0.113.7'));
		$this->assertSame(array($net4), $this->activeBlocks('198.51.100.200'));
		$this->assertSame(array(), $this->activeBlocks('198.51.101.1'));
		$this->assertSame(array($net6), $this->activeBlocks('2001:db8:ab:1::5'));
		$this->assertSame(array(), $this->activeBlocks('2001:db8:ac::1'));
		$this->assertSame(array($exact6), $this->activeBlocks('2001:db8::9'), 'stored in upper case');
		$this->assertSame(array(), $this->activeBlocks('192.0.2.1'), 'corrupted entries must not match');
		$this->assertSame(array(), $this->activeBlocks('203.0.113.8'), 'unblocked');
		$this->assertTrue($this->helper->isIPBlocked('198.51.100.1'));
		$this->assertFalse($this->helper->isIPBlocked('192.0.2.200'));
	}

	public function testNumberOfPreviousBlocks()
	{
		$this->block('203.0.113.7', 500000, 0);
		$this->block('203.0.113.7', 10, 60);
		$manuallyUnblocked = $this->block('203.0.113.8', 10, 60);
		$this->insert('#__bfstop_unblock', array('block_id' => $manuallyUnblocked, 'source' => 0, 'crdate' => self::minutesAgo(0)));
		$unblockedByMail = $this->block('203.0.113.9', 10, 60);
		$this->insert('#__bfstop_unblock', array('block_id' => $unblockedByMail, 'source' => 1, 'crdate' => self::minutesAgo(0)));

		$this->assertSame(2, $this->helper->getNumberOfPreviousBlocks('203.0.113.7'));
		$this->assertSame(0, $this->helper->getNumberOfPreviousBlocks('203.0.113.8'));
		$this->assertSame(1, $this->helper->getNumberOfPreviousBlocks('203.0.113.9'));
	}

	public function testBlockIPAndRecordAttempts()
	{
		$this->failedLogin('203.0.113.50', 'bob', 0);
		$id = $this->helper->blockIP((object) array('ipaddress' => '203.0.113.50', 'username' => 'bob'), 30, false, '');
		$this->assertGreaterThan(0, $id);
		$this->assertSame(array($id), $this->activeBlocks('203.0.113.50'));
		$this->assertSame(0, $this->helper->getNumberOfFailedLogins(60, '203.0.113.50', self::minutesAgo(0)),
			'failed logins are marked handled when blocking');

		$this->helper->recordBlockedAttempt(array($id));
		$this->helper->recordBlockedAttempt(array($id));
		$this->db->setQuery('SELECT attempts, last_attempt FROM #__bfstop_bannedip WHERE id='.$id);
		$row = $this->db->loadObject();
		$this->assertSame(2, (int) $row->attempts);
		$this->assertNotNull($row->last_attempt);
	}

	public function testAllowList()
	{
		$this->insert('#__bfstop_allowlist', array('ipaddress' => '10.1.0.0/16', 'notes' => ''));
		$this->insert('#__bfstop_allowlist', array('ipaddress' => '2001:DB8:FFFF::1', 'notes' => ''));
		$this->insert('#__bfstop_allowlist', array('ipaddress' => '198.51.100.3', 'notes' => ''));

		$this->assertTrue($this->helper->isIPOnAllowList('10.1.2.3'));
		$this->assertFalse($this->helper->isIPOnAllowList('10.2.0.1'));
		$this->assertTrue($this->helper->isIPOnAllowList('2001:db8:ffff::1'));
		$this->assertTrue($this->helper->isIPOnAllowList('198.51.100.3'));
		$this->assertFalse($this->helper->isIPOnAllowList('198.51.100.30'));
	}

	public function testUnblockToken()
	{
		$this->assertSame('tokenA', $this->helper->getNewUnblockToken(1, 'tokenA'));
		$this->assertNull($this->queryValue("SELECT username FROM #__bfstop_unblock_token WHERE token='tokenA'"));
		$this->assertFalse($this->helper->hasCurrentUnblockToken('Someone'));
		$this->assertSame('tokenU', $this->helper->getNewUnblockToken(2, 'tokenU', 'Someone'));
		$this->assertTrue($this->helper->hasCurrentUnblockToken('someone'), 'case-insensitive');
		$this->assertFalse($this->helper->hasCurrentUnblockToken('Somebody-else'));
		$this->insert('#__bfstop_unblock_token', array('token' => 'tokenOld', 'block_id' => 3,
			'crdate' => self::minutesAgo(4 * 24 * 60), 'username' => 'Expired'));
		$this->assertFalse($this->helper->hasCurrentUnblockToken('Expired'), 'an expired token is not current');
		$this->assertTrue($this->helper->unblockTokenExists('tokenA'));
		$this->assertFalse($this->helper->unblockTokenExists('tokenB'));
	}

	public function testKnownIpUsername()
	{
		$login = (object) array('ipaddress' => '203.0.113.5', 'username' => 'bob');
		$this->helper->successfulLogin($login);
		$this->helper->successfulLogin($login); // second time: update instead of insert
		$this->assertTrue($this->helper->hasLoggedInFrom('203.0.113.5', 'bob', 64));
		$this->assertFalse($this->helper->hasLoggedInFrom('203.0.113.5', 'eve', 64));
		$this->assertFalse($this->helper->hasLoggedInFrom('203.0.113.6', 'bob', 64));
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip'));
	}

	private function knownRows()
	{
		$this->db->setQuery('SELECT ipaddress, username FROM #__bfstop_knownip ORDER BY id');
		return array_map(fn ($row) => $row->ipaddress.' '.$row->username, $this->db->loadObjectList());
	}

	public function testIpv6ClientsAreRememberedByNetwork()
	{
		// the privacy extensions give an IPv6 client a new address every day:
		// one row per address would pile up, and none of them match tomorrow
		$net = '2001:db8:1:2::/64';
		$this->helper->successfulLogin((object) array('ipaddress' => '2001:db8:1:2:aaaa::1', 'username' => 'bob'), $net);
		$this->helper->successfulLogin((object) array('ipaddress' => '2001:db8:1:2:bbbb::2', 'username' => 'bob'), $net);
		$this->assertSame(array($net.' bob'), $this->knownRows());
		$this->assertTrue($this->helper->hasLoggedInFrom('2001:db8:1:2:cccc::3', 'bob', 64), 'a third address of the network');
		$this->assertFalse($this->helper->hasLoggedInFrom('2001:db8:1:3::1', 'bob', 64), 'another network');
		$this->assertFalse($this->helper->hasLoggedInFrom('2001:db8:1:2:cccc::3', 'eve', 64), 'another user');
	}

	public function testKnownIpUsernameIsCaseInsensitive()
	{
		$this->helper->successfulLogin((object) array('ipaddress' => '203.0.113.5', 'username' => 'Bob'));
		$this->helper->successfulLogin((object) array('ipaddress' => '203.0.113.5', 'username' => 'bob'));
		$this->assertSame(array('203.0.113.5 Bob'), $this->knownRows(), 'one row, not one per spelling');
		$this->assertTrue($this->helper->hasLoggedInFrom('203.0.113.5', 'BOB', 64));
	}

	public function testSuccessfulLoginHandlesFailuresRecordedUnderTheNetwork()
	{
		$net = '2001:db8:1:2::/64';
		$this->failedLogin($net, 'bob', 0);
		$this->failedLogin($net, 'eve', 0);
		$this->helper->successfulLogin((object) array('ipaddress' => '2001:db8:1:2::9', 'username' => 'bob'), $net);
		$this->assertSame(1, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE handled=0"), 'only bob\'s');
	}

	public function testEarlierRecordingsAreStillRecognised()
	{
		$row = fn ($ip) => $this->insert('#__bfstop_knownip', array('ipaddress' => $ip, 'username' => 'bob',
			'first_success' => self::minutesAgo(10), 'last_success' => self::minutesAgo(5)));
		// recorded by address (earlier version), now looked up by network
		$row('2001:db8:1:2:aaaa::1');
		$this->assertTrue($this->helper->hasLoggedInFrom('2001:db8:1:2:bbbb::2', 'bob', 64));
		$this->assertFalse($this->helper->hasLoggedInFrom('2001:db8:1:3::2', 'bob', 64));
		// the same address in another spelling
		$this->assertTrue($this->helper->hasLoggedInFrom('2001:0DB8:1:2:AAAA:0:0:1', 'bob', 128));
		// recorded by network, then the setting was changed to single addresses
		$row('2001:db8:5:6::/64');
		$this->assertTrue($this->helper->hasLoggedInFrom('2001:db8:5:6::77', 'bob', 128));
		$this->assertFalse($this->helper->hasLoggedInFrom('2001:db8:5:7::77', 'bob', 128));
		// IPv4 is only ever matched exactly
		$row('203.0.113.5');
		$this->assertTrue($this->helper->hasLoggedInFrom('203.0.113.5', 'bob', 64));
		$this->assertFalse($this->helper->hasLoggedInFrom('203.0.113.6', 'bob', 64));
	}

	public function testPruneKnownIpsForgetsOldLogins()
	{
		$row = fn ($ip, $daysAgo) => $this->insert('#__bfstop_knownip', array('ipaddress' => $ip, 'username' => 'bob',
			'first_success' => self::minutesAgo($daysAgo * 1440 + 1), 'last_success' => self::minutesAgo($daysAgo * 1440)));
		$row('203.0.113.1', 400);
		$row('203.0.113.2', 364);
		$row('203.0.113.3', 1);
		$this->helper->pruneKnownIps();
		$this->assertSame(array('203.0.113.2 bob', '203.0.113.3 bob'), $this->knownRows());
	}

	public function testPruneKnownIpsKeepsTheNewestRows()
	{
		$row = fn ($ip, $daysAgo) => $this->insert('#__bfstop_knownip', array('ipaddress' => $ip, 'username' => 'bob',
			'first_success' => self::minutesAgo($daysAgo * 1440 + 1), 'last_success' => self::minutesAgo($daysAgo * 1440)));
		$row('203.0.113.1', 30);
		$row('203.0.113.2', 10);
		$row('203.0.113.3', 20);
		$row('203.0.113.4', 5);
		$this->helper->pruneKnownIps(365, 10);
		$this->assertCount(4, $this->knownRows(), 'below the limit');
		$this->helper->pruneKnownIps(365, 2);
		$this->assertSame(array('203.0.113.2 bob', '203.0.113.4 bob'), $this->knownRows());
	}

	public function testPurgeExpiredUnblockTokens()
	{
		$this->insert('#__bfstop_unblock_token', array('token' => 'tokenOld', 'block_id' => 1,
			'crdate' => self::minutesAgo(3 * 24 * 60 + 5)));
		$this->insert('#__bfstop_unblock_token', array('token' => 'tokenNew', 'block_id' => 2,
			'crdate' => self::minutesAgo(3 * 24 * 60 - 5)));
		$this->helper->purgeExpiredUnblockTokens();
		$this->db->setQuery('SELECT token FROM #__bfstop_unblock_token');
		$this->assertSame(array('tokenNew'), $this->db->loadColumn());
	}

	public function testDnsCache()
	{
		$this->assertFalse($this->helper->getCachedHostname('203.0.113.5'), 'not cached');
		$this->helper->cacheHostname('203.0.113.5', 'host.example');
		$this->assertSame('host.example', $this->helper->getCachedHostname('203.0.113.5'));
		$this->helper->cacheHostname('203.0.113.5', null);
		$this->assertNull($this->helper->getCachedHostname('203.0.113.5'), 'cached "no PTR record"');
	}

	public function testPurgeOldEntries()
	{
		$this->failedLogin('203.0.113.5', 'old', 8 * 24 * 60);
		$this->failedLogin('203.0.113.5', 'recent', 60);
		$oldExpiredBlock = $this->block('203.0.113.60', 10 * 24 * 60, 60);
		$oldUnlimitedBlock = $this->block('203.0.113.61', 10 * 24 * 60, 0);
		$this->insert('#__bfstop_unblock', array('block_id' => $oldExpiredBlock, 'source' => 0, 'crdate' => self::minutesAgo(0)));
		$this->insert('#__bfstop_unblock_token', array('token' => 'old', 'block_id' => $oldExpiredBlock, 'crdate' => self::minutesAgo(8 * 24 * 60)));
		$this->insert('#__bfstop_dnscache', array('ipaddress' => '203.0.113.77', 'hostname' => null, 'checked_at' => self::minutesAgo(8 * 24 * 60)));
		$this->insert('#__bfstop_dnscache', array('ipaddress' => '203.0.113.78', 'hostname' => null, 'checked_at' => self::minutesAgo(60)));

		$this->helper->purgeOldEntries(1);

		$this->assertSame('recent', $this->queryValue('SELECT username FROM #__bfstop_failedlogin'));
		$this->assertSame(array($oldUnlimitedBlock), array_map('intval', $this->db->setQuery('SELECT id FROM #__bfstop_bannedip')->loadColumn()));
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock'), 'unblock of purged block');
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock_token'));
		$this->assertSame('203.0.113.78', $this->queryValue('SELECT ipaddress FROM #__bfstop_dnscache'));
	}

	public function testSaveLastPurgeChangesOnlyThatValue()
	{
		$original = $this->getPluginParams();
		try
		{
			// what an administrator saved after the request started must survive
			$this->setPluginParams(json_encode(array('blockNumber' => 7, 'lastPurge' => 1)));
			$this->helper->saveLastPurge(1700000000);
			$saved = json_decode($this->getPluginParams(), true);
			$this->assertSame(array('blockNumber' => 7, 'lastPurge' => 1700000000), $saved);
		}
		finally
		{
			$this->setPluginParams($original);
		}
	}

	public function testTrimUsernameStatsKeepsTheMostAttackedAndMostRecent()
	{
		$names = array(
			// username => [attempts, minutes since last attempt]
			'many-old'   => array(50, 5000),
			'few-old'    => array(1, 5000),
			'few-older'  => array(1, 9000),
			'few-recent' => array(1, 10),
			'some'       => array(5, 100),
		);
		foreach ($names as $name => $data)
		{
			$this->insert('#__bfstop_username_stats', array('username' => $name, 'attempts' => $data[0],
				'first_attempt' => self::minutesAgo($data[1] + 1), 'last_attempt' => self::minutesAgo($data[1])));
		}
		$this->helper->trimUsernameStats(10);
		$this->assertSame(5, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_username_stats'));

		$this->helper->trimUsernameStats(3);
		$this->db->setQuery('SELECT username FROM #__bfstop_username_stats ORDER BY username');
		$this->assertSame(array('few-recent', 'many-old', 'some'), $this->db->loadColumn());
	}

	public function testLineBreaksInUsernamesDoNotForgeLinesInTheMailedList()
	{
		$this->failedLogin('203.0.113.5', "bob\n[forged] 203.0.113.99", 1);
		$list = $this->helper->getFormattedFailedList('203.0.113.5', self::minutesAgo(0), 60);
		// header, separator and the one entry
		$this->assertCount(3, array_filter(explode("\n", $list), 'strlen'));
	}
}
