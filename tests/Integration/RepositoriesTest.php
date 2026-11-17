<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Helper\NotifierHelper;
use Codeling\Library\Bfstop\Origin;
use Codeling\Library\Bfstop\Repository\BlockRepository;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Repository\UnblockTokenRepository;
use Codeling\Library\Bfstop\Service\BlockService;
use Codeling\Library\Bfstop\Service\LoginService;
use Codeling\Library\Bfstop\Service\Maintenance;
use Joomla\Registry\Registry;

/**
 * Runs every query of the repositories, and of the services made of them,
 * against the actual database.
 */
class RepositoriesTest extends IntegrationTestCase
{
	private $repos;
	private $logins;
	private $blocker;
	private $maintenance;
	private $notifier;

	protected function setUp(): void
	{
		parent::setUp();
		$this->repos = new Repositories($this->logger);
		$this->logins = new LoginService($this->repos);
		$this->blocker = new BlockService($this->repos);
		$this->maintenance = new Maintenance($this->repos);
		$this->notifier = new NotifierHelper($this->logger, $this->repos, '', -1, -1, false);
	}

	private function failedLogin($ip, $username, $minutesAgo, $origin = 0)
	{
		$this->logins->recordFailedLogin((object) array('ipaddress' => $ip,
			'logtime' => self::minutesAgo($minutesAgo), 'username' => $username, 'origin' => $origin));
	}

	private function block($ip, $minutesAgo, $duration)
	{
		return $this->insert('#__bfstop_bannedip', array('ipaddress' => $ip,
			'crdate' => self::minutesAgo($minutesAgo), 'duration' => $duration), 'id');
	}

	private function activeBlocks($ip)
	{
		$ids = $this->repos->blocks()->activeIdsFor($ip);
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

		$this->assertSame(3, $this->repos->failedLogins()->countUnhandledFromAddress(60, '203.0.113.5', $now));
		$this->assertSame(4, $this->repos->failedLogins()->countUnhandledFromAddress(180, '203.0.113.5', $now));
		$this->assertSame(4, $this->repos->failedLogins()->countUnhandledForUsername(60, 'bob', $now));
		$this->assertSame(4, (int) $this->repos->failedLogins()->countInLastHour());
		$list = $this->notifier->failedLoginList('203.0.113.5', $now, 60);
		$this->assertSame(3 + 2, substr_count($list, "\n"), "2 header lines + 3 entries:\n".$list);

		$this->repos->failedLogins()->markHandled('203.0.113.5', 'bob');
		$this->assertSame(0, $this->repos->failedLogins()->countUnhandledFromAddress(60, '203.0.113.5', $now));
		$this->assertSame(1, $this->repos->failedLogins()->countUnhandledForUsername(60, 'bob', $now), 'other IP not handled');
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
		$this->maintenance->purgeOldEntries(1);
		$this->assertSame(3, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_username_stats'));
	}

	/** what the update does to the entries of earlier versions (see the installer script) */
	private function convertStoredAddresses()
	{
		require_once BFSTOP_PLUGIN_ROOT.'/updatescript.php';
		return \PlgsystembfstopInstallerScript::canonicalizeAddresses($this->db);
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
		// entries of earlier versions (and typed by hand) are not in the canonical
		// form the lookup relies on: the upper case ones are the two IPv6 entries
		$this->assertSame(2, $this->convertStoredAddresses());

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
		$this->assertTrue($this->repos->blocks()->isBlocked('198.51.100.1'));
		$this->assertFalse($this->repos->blocks()->isBlocked('192.0.2.200'));
	}

	public function testNumberOfPreviousBlocks()
	{
		$this->block('203.0.113.7', 500000, 0);
		$this->block('203.0.113.7', 10, 60);
		$manuallyUnblocked = $this->block('203.0.113.8', 10, 60);
		$this->insert('#__bfstop_unblock', array('block_id' => $manuallyUnblocked, 'source' => 0, 'crdate' => self::minutesAgo(0)));
		$unblockedByMail = $this->block('203.0.113.9', 10, 60);
		$this->insert('#__bfstop_unblock', array('block_id' => $unblockedByMail, 'source' => 1, 'crdate' => self::minutesAgo(0)));

		$this->assertSame(2, $this->repos->blocks()->countPrevious('203.0.113.7'));
		$this->assertSame(0, $this->repos->blocks()->countPrevious('203.0.113.8'));
		$this->assertSame(1, $this->repos->blocks()->countPrevious('203.0.113.9'));
	}

	public function testBlockIPAndRecordAttempts()
	{
		$this->failedLogin('203.0.113.50', 'bob', 0);
		$id = $this->blocker->block((object) array('ipaddress' => '203.0.113.50', 'username' => 'bob'), 30, false, '');
		$this->assertGreaterThan(0, $id);
		$this->assertSame(array($id), $this->activeBlocks('203.0.113.50'));
		$this->assertSame(0, $this->repos->failedLogins()->countUnhandledFromAddress(60, '203.0.113.50', self::minutesAgo(0)),
			'failed logins are marked handled when blocking');

		$this->repos->blocks()->recordAttempt(array($id));
		$this->repos->blocks()->recordAttempt(array($id));
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
		$this->assertSame(1, $this->convertStoredAddresses());

		$this->assertTrue($this->repos->allowList()->contains('10.1.2.3'));
		$this->assertFalse($this->repos->allowList()->contains('10.2.0.1'));
		$this->assertTrue($this->repos->allowList()->contains('2001:db8:ffff::1'));
		$this->assertTrue($this->repos->allowList()->contains('198.51.100.3'));
		$this->assertFalse($this->repos->allowList()->contains('198.51.100.30'));
	}

	public function testUnblockToken()
	{
		$this->assertSame('tokenA', $this->repos->unblockTokens()->add(1, 'tokenA'));
		$this->assertNull($this->queryValue("SELECT username FROM #__bfstop_unblock_token WHERE token='".UnblockTokenRepository::hash('tokenA')."'"));
		// only the hash is stored: the table doesn't hold what the link needs
		$this->assertSame(0, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_unblock_token WHERE token='tokenA'"));
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock_token WHERE block_id=1'));
		$this->assertFalse($this->repos->unblockTokens()->hasCurrentFor('Someone'));
		$this->assertSame('tokenU', $this->repos->unblockTokens()->add(2, 'tokenU', 'Someone'));
		$this->assertTrue($this->repos->unblockTokens()->hasCurrentFor('someone'), 'case-insensitive');
		$this->assertFalse($this->repos->unblockTokens()->hasCurrentFor('Somebody-else'));
		$this->insert('#__bfstop_unblock_token', array('token' => 'tokenOld', 'block_id' => 3,
			'crdate' => self::minutesAgo(4 * 24 * 60), 'username' => 'Expired'));
		$this->assertFalse($this->repos->unblockTokens()->hasCurrentFor('Expired'), 'an expired token is not current');
		$this->assertTrue($this->repos->unblockTokens()->exists('tokenA'));
		$this->assertFalse($this->repos->unblockTokens()->exists('tokenB'));
	}

	public function testUnblockTokenIsIssuedForItsBlock()
	{
		$tokens = $this->repos->unblockTokens();
		$blockId = $this->insert('#__bfstop_bannedip', array('ipaddress' => '2001:db8:7::/56',
			'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		$tokens->add($blockId, 'tokenI');
		$this->assertSame(array('blockId' => $blockId, 'address' => '2001:db8:7::/56'), $tokens->issuedFor('tokenI'));
		$this->assertNull($tokens->issuedFor('tokenX'), 'no such token');
		// the stored hash is no token
		$this->assertNull($tokens->issuedFor(UnblockTokenRepository::hash('tokenI')));

		$this->insert('#__bfstop_unblock_token', array('token' => 'tokenOld', 'block_id' => $blockId,
			'crdate' => self::minutesAgo(4 * 24 * 60)));
		$this->assertNull($tokens->issuedFor('tokenOld'), 'expired');

		$tokens->add($blockId + 1000, 'tokenOrphan');
		$this->assertNull($tokens->issuedFor('tokenOrphan'), 'its block is gone');

		$this->assertTrue($tokens->remove('tokenI'));
		$this->assertNull($tokens->issuedFor('tokenI'), 'used up');
		$this->assertFalse($tokens->exists('tokenI'));
		$this->assertTrue($tokens->exists('tokenOld'), 'only the token used is deleted');
	}

	public function testLiftingABlock()
	{
		$blocks = $this->repos->blocks();
		$id = $this->insert('#__bfstop_bannedip', array('ipaddress' => '203.0.113.90',
			'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		$this->assertTrue($blocks->isBlocked('203.0.113.90'));
		$this->assertTrue($blocks->lift(array((string) $id), BlockRepository::LiftedByToken));
		$this->assertFalse($blocks->isBlocked('203.0.113.90'));
		$this->assertSame(BlockRepository::LiftedByToken,
			(int) $this->queryValue('SELECT source FROM #__bfstop_unblock WHERE block_id='.$id));
		// lifting it again changes nothing, and is no failure
		$this->assertTrue($blocks->lift(array($id), BlockRepository::LiftedByAdministrator));
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock WHERE block_id='.$id));
	}

	public function testTokenHashFitsTheColumnAndIsStable()
	{
		$hash = UnblockTokenRepository::hash('abc');
		$this->assertMatchesRegularExpression('/^[0-9a-f]{40}$/', $hash);
		$this->assertSame($hash, UnblockTokenRepository::hash('abc'));
		$this->assertNotSame($hash, UnblockTokenRepository::hash('abd'));
		// a stored hash is no token which unblocks: it would be hashed again
		$this->repos->unblockTokens()->add(1, 'tokenA');
		$this->assertFalse($this->repos->unblockTokens()->exists(UnblockTokenRepository::hash('tokenA')));
	}

	public function testKnownIpUsername()
	{
		$login = (object) array('ipaddress' => '203.0.113.5', 'username' => 'bob');
		$this->logins->recordSuccessfulLogin($login);
		$this->logins->recordSuccessfulLogin($login); // second time: update instead of insert
		$this->assertTrue($this->repos->knownIps()->hasLoggedInFrom('203.0.113.5', 'bob', 64));
		$this->assertFalse($this->repos->knownIps()->hasLoggedInFrom('203.0.113.5', 'eve', 64));
		$this->assertFalse($this->repos->knownIps()->hasLoggedInFrom('203.0.113.6', 'bob', 64));
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
		$this->logins->recordSuccessfulLogin((object) array('ipaddress' => '2001:db8:1:2:aaaa::1', 'username' => 'bob'), $net);
		$this->logins->recordSuccessfulLogin((object) array('ipaddress' => '2001:db8:1:2:bbbb::2', 'username' => 'bob'), $net);
		$this->assertSame(array($net.' bob'), $this->knownRows());
		$this->assertTrue($this->repos->knownIps()->hasLoggedInFrom('2001:db8:1:2:cccc::3', 'bob', 64), 'a third address of the network');
		$this->assertFalse($this->repos->knownIps()->hasLoggedInFrom('2001:db8:1:3::1', 'bob', 64), 'another network');
		$this->assertFalse($this->repos->knownIps()->hasLoggedInFrom('2001:db8:1:2:cccc::3', 'eve', 64), 'another user');
	}

	public function testKnownIpUsernameIsCaseInsensitive()
	{
		$this->logins->recordSuccessfulLogin((object) array('ipaddress' => '203.0.113.5', 'username' => 'Bob'));
		$this->logins->recordSuccessfulLogin((object) array('ipaddress' => '203.0.113.5', 'username' => 'bob'));
		$this->assertSame(array('203.0.113.5 Bob'), $this->knownRows(), 'one row, not one per spelling');
		$this->assertTrue($this->repos->knownIps()->hasLoggedInFrom('203.0.113.5', 'BOB', 64));
	}

	public function testSuccessfulLoginHandlesFailuresRecordedUnderTheNetwork()
	{
		$net = '2001:db8:1:2::/64';
		$this->failedLogin($net, 'bob', 0);
		$this->failedLogin($net, 'eve', 0);
		$this->logins->recordSuccessfulLogin((object) array('ipaddress' => '2001:db8:1:2::9', 'username' => 'bob'), $net);
		$this->assertSame(1, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE handled=0"), 'only bob\'s');
	}

	public function testEarlierRecordingsAreStillRecognised()
	{
		$row = fn ($ip) => $this->insert('#__bfstop_knownip', array('ipaddress' => $ip, 'username' => 'bob',
			'first_success' => self::minutesAgo(10), 'last_success' => self::minutesAgo(5)));
		// recorded by address (earlier version), now looked up by network
		$row('2001:db8:1:2:aaaa::1');
		$this->assertTrue($this->repos->knownIps()->hasLoggedInFrom('2001:db8:1:2:bbbb::2', 'bob', 64));
		$this->assertFalse($this->repos->knownIps()->hasLoggedInFrom('2001:db8:1:3::2', 'bob', 64));
		// the same address in another spelling
		$this->assertTrue($this->repos->knownIps()->hasLoggedInFrom('2001:0DB8:1:2:AAAA:0:0:1', 'bob', 128));
		// recorded by network, then the setting was changed to single addresses
		$row('2001:db8:5:6::/64');
		$this->assertTrue($this->repos->knownIps()->hasLoggedInFrom('2001:db8:5:6::77', 'bob', 128));
		$this->assertFalse($this->repos->knownIps()->hasLoggedInFrom('2001:db8:5:7::77', 'bob', 128));
		// IPv4 is only ever matched exactly
		$row('203.0.113.5');
		$this->assertTrue($this->repos->knownIps()->hasLoggedInFrom('203.0.113.5', 'bob', 64));
		$this->assertFalse($this->repos->knownIps()->hasLoggedInFrom('203.0.113.6', 'bob', 64));
	}

	public function testPruneKnownIpsForgetsOldLogins()
	{
		$row = fn ($ip, $daysAgo) => $this->insert('#__bfstop_knownip', array('ipaddress' => $ip, 'username' => 'bob',
			'first_success' => self::minutesAgo($daysAgo * 1440 + 1), 'last_success' => self::minutesAgo($daysAgo * 1440)));
		$row('203.0.113.1', 400);
		$row('203.0.113.2', 364);
		$row('203.0.113.3', 1);
		$this->repos->knownIps()->prune();
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
		$this->repos->knownIps()->prune(365, 10);
		$this->assertCount(4, $this->knownRows(), 'below the limit');
		$this->repos->knownIps()->prune(365, 2);
		$this->assertSame(array('203.0.113.2 bob', '203.0.113.4 bob'), $this->knownRows());
	}

	public function testPurgeExpiredUnblockTokens()
	{
		$this->insert('#__bfstop_unblock_token', array('token' => 'tokenOld', 'block_id' => 1,
			'crdate' => self::minutesAgo(3 * 24 * 60 + 5)));
		$this->insert('#__bfstop_unblock_token', array('token' => 'tokenNew', 'block_id' => 2,
			'crdate' => self::minutesAgo(3 * 24 * 60 - 5)));
		$this->repos->unblockTokens()->purgeExpired();
		$this->db->setQuery('SELECT token FROM #__bfstop_unblock_token');
		$this->assertSame(array(UnblockTokenRepository::hash('tokenNew')), $this->db->loadColumn());
	}

	public function testDnsCache()
	{
		$this->assertFalse($this->repos->dnsCache()->get('203.0.113.5'), 'not cached');
		$this->repos->dnsCache()->put('203.0.113.5', 'host.example');
		$this->assertSame('host.example', $this->repos->dnsCache()->get('203.0.113.5'));
		$this->repos->dnsCache()->put('203.0.113.5', null);
		$this->assertNull($this->repos->dnsCache()->get('203.0.113.5'), 'cached "no PTR record"');
	}

	public function testClientNames()
	{
		// the origin of a failed login: the client id of the application
		$this->assertSame('Frontend', Origin::name(0));
		$this->assertSame('Backend', Origin::name(1));
		$this->assertSame('API', Origin::name(3));
	}

	public function testPurgeOldEntries()
	{
		$this->failedLogin('203.0.113.5', 'old', 8 * 24 * 60);
		$this->failedLogin('203.0.113.5', 'recent', 60);
		$oldExpiredBlock = $this->block('203.0.113.60', 10 * 24 * 60, 60);
		$oldUnlimitedBlock = $this->block('203.0.113.61', 10 * 24 * 60, 0);
		$this->insert('#__bfstop_unblock', array('block_id' => $oldExpiredBlock, 'source' => 0, 'crdate' => self::minutesAgo(0)));
		$this->insert('#__bfstop_unblock_token', array('token' => 'old', 'block_id' => $oldExpiredBlock, 'crdate' => self::minutesAgo(8 * 24 * 60)));

		$this->maintenance->purgeOldEntries(1);

		$this->assertSame('recent', $this->queryValue('SELECT username FROM #__bfstop_failedlogin'));
		$this->assertSame(array($oldUnlimitedBlock), array_map('intval', $this->db->setQuery('SELECT id FROM #__bfstop_bannedip')->loadColumn()));
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock'), 'unblock of purged block');
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock_token'));
	}

	public function testPruneDnsCacheRemovesExpiredAndKeepsTheNewestRows()
	{
		$row = fn ($ip, $minutesAgo) => $this->insert('#__bfstop_dnscache',
			array('ipaddress' => $ip, 'hostname' => null, 'checked_at' => self::minutesAgo($minutesAgo)));
		$row('2001:db8::1', 8 * 24 * 60);   // expired
		$row('2001:db8::2', 30);
		$row('2001:db8::3', 90);
		$row('2001:db8::4', 10);
		$addresses = fn () => $this->db->setQuery('SELECT ipaddress FROM #__bfstop_dnscache ORDER BY ipaddress')->loadColumn();
		$this->repos->dnsCache()->prune(null, 10);
		$this->assertSame(array('2001:db8::2', '2001:db8::3', '2001:db8::4'), $addresses());
		$this->repos->dnsCache()->prune(null, 2);
		$this->assertSame(array('2001:db8::2', '2001:db8::4'), $addresses());
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
		$this->repos->usernameStats()->trim(10);
		$this->assertSame(5, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_username_stats'));

		$this->repos->usernameStats()->trim(3);
		$this->db->setQuery('SELECT username FROM #__bfstop_username_stats ORDER BY username');
		$this->assertSame(array('few-recent', 'many-old', 'some'), $this->db->loadColumn());
	}

	public function testLineBreaksInUsernamesDoNotForgeLinesInTheMailedList()
	{
		$this->failedLogin('203.0.113.5', "bob\n[forged] 203.0.113.99", 1);
		$list = $this->notifier->failedLoginList('203.0.113.5', self::minutesAgo(0), 60);
		// header, separator and the one entry
		$this->assertCount(3, array_filter(explode("\n", $list), 'strlen'));
	}

	public function testAddressesWithoutActiveBlock()
	{
		$block = function ($ip, $minutesAgo, $duration)
		{
			return $this->insert('#__bfstop_bannedip', array('ipaddress' => $ip,
				'crdate' => self::minutesAgo($minutesAgo), 'duration' => $duration), 'id');
		};
		$block('203.0.113.1', 120, 60);                  // ran out
		$block('203.0.113.2', 10, 60);                   // active
		$block('203.0.113.3', 5000, 0);                  // permanent
		$lifted = $block('203.0.113.4', 10, 60);         // lifted by an administrator
		$this->insert('#__bfstop_unblock', array('block_id' => $lifted, 'source' => 0, 'crdate' => self::minutesAgo(1)));
		$block('203.0.113.5', 120, 60);                  // ran out, but blocked again since
		$block('203.0.113.5', 10, 60);
		$addresses = $this->repos->blocks()->addressesWithoutActiveBlock();
		sort($addresses);
		$this->assertSame(array('203.0.113.1', '203.0.113.4'), $addresses);
	}

	public function testBlockedAddresses()
	{
		$this->assertSame(array(), $this->repos->blocks()->allAddresses());
		foreach (array(array('203.0.113.1', 120), array('203.0.113.2', 10), array('203.0.113.2', 300),
			array('2001:db8:1::/56', 10)) as list($ip, $minutesAgo))
		{
			$this->insert('#__bfstop_bannedip', array('ipaddress' => $ip,
				'crdate' => self::minutesAgo($minutesAgo), 'duration' => 60));
		}
		$addresses = $this->repos->blocks()->allAddresses();
		sort($addresses);
		$this->assertSame(array('2001:db8:1::/56', '203.0.113.1', '203.0.113.2'), $addresses);
	}

	public function testFailedLoginsAreLimited()
	{
		for ($i = 0; $i < 12; ++$i)
		{
			$this->failedLogin('203.0.113.5', 'user'.$i, 100 - $i);
		}
		$this->repos->failedLogins()->trim(20);
		$this->assertSame(12, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'));
		$this->repos->failedLogins()->trim(5);
		$this->assertSame(5, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'));
		// the newest are kept
		$this->db->setQuery('SELECT username FROM #__bfstop_failedlogin ORDER BY id');
		$this->assertSame(array('user7', 'user8', 'user9', 'user10', 'user11'), $this->db->loadColumn());
	}

	public function testBlocksAreStoredInCanonicalForm()
	{
		$this->blocker->block((object) array('ipaddress' => '2001:DB8::5', 'logtime' => self::minutesAgo(0),
			'username' => 'x', 'origin' => 0), 60, false, '');
		$this->assertSame('2001:db8::5', $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));
		$this->assertTrue($this->repos->blocks()->isBlocked('2001:db8::5'));
		$this->assertTrue($this->repos->blocks()->isBlocked('2001:DB8:0:0:0:0:0:5'));
	}

	public function testLookupDoesNotLoadWhatCannotMatch()
	{
		// networks of the other address family, and of other prefixes, are no candidates
		$this->block('2001:db8::/32', 0, 60);
		$this->block('203.0.113.0/24', 0, 60);
		$this->block('203.0.114.0/24', 0, 60);
		$this->assertCount(1, $this->repos->blocks()->activeIdsFor('203.0.113.9'));
		$this->assertCount(1, $this->repos->blocks()->activeIdsFor('2001:db8:5::1'));
		$this->assertSame(array(), $this->repos->blocks()->activeIdsFor(''));
		$this->assertSame(array(), $this->repos->blocks()->activeIdsFor('203.0.113.0/24'), 'a network is no client address');
	}

	public function testAllowListEntriesOverlapping()
	{
		$this->insert('#__bfstop_allowlist', array('ipaddress' => '203.0.113.7', 'notes' => ''));
		$this->insert('#__bfstop_allowlist', array('ipaddress' => '2001:db8:1:7f::9', 'notes' => ''));
		// isIPOnAllowList() only answers for an address
		$this->assertFalse($this->repos->allowList()->contains('203.0.113.0/24'));
		$this->assertSame(array('203.0.113.7'), $this->repos->allowList()->entriesOverlapping('203.0.113.0/24'));
		$this->assertSame(array('2001:db8:1:7f::9'), $this->repos->allowList()->entriesOverlapping('2001:db8:1::/56'));
		$this->assertSame(array(), $this->repos->allowList()->entriesOverlapping('198.51.100.0/24'));
	}
}
