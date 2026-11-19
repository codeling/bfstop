<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Helper\NotifierHelper;
use Codeling\Library\Bfstop\Repository\BlockRepository;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\BlockPolicy;
use Codeling\Library\Bfstop\Service\LoginService;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\Registry\Registry;

/**
 * What the settings make of a failed login, on its own: FailedLoginTest runs
 * the whole plugin, which shows that something is blocked, delayed or mailed,
 * but not where each of the rules has its edges (the threshold, the cap of the
 * progressive durations, the thresholds of the adaptive delay, ...).
 */
class BlockPolicyTest extends IntegrationTestCase
{
	private const Ip = '203.0.113.7';

	private static $originalParams;
	private $repos;
	private $createdUsers = array();

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
		$db->setQuery("SELECT params FROM #__extensions WHERE type='component' AND element='com_bfstop'");
		self::$originalParams = $db->loadResult();
	}

	public static function tearDownAfterClass(): void
	{
		// some tests change the settings the IpHelper reads (trusted proxies)
		if (self::$originalParams !== null)
		{
			$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
			self::storeSettings($db, self::$originalParams);
		}
	}

	protected function setUp(): void
	{
		parent::setUp();
		$this->repos = new Repositories($this->logger);
	}

	protected function tearDown(): void
	{
		foreach ($this->createdUsers as $id)
		{
			$this->db->setQuery('DELETE FROM #__users WHERE id='.(int) $id);
			$this->db->execute();
		}
		$this->createdUsers = array();
	}

	private function policy(array $params = array()): BlockPolicy
	{
		return new BlockPolicy(new Registry($params), $this->repos, new LoginService($this->repos), $this->logger);
	}

	private function entry($username = 'bob', $ip = self::Ip, $minutesAgo = 0)
	{
		return (object) array('ipaddress' => $ip, 'username' => $username,
			'logtime' => self::minutesAgo($minutesAgo), 'origin' => 0);
	}

	private function failedLogins($count, $minutesAgo = 1, $username = 'bob', $ip = self::Ip, $handled = 0)
	{
		for ($i = 0; $i < $count; ++$i)
		{
			$this->insert('#__bfstop_failedlogin', array('ipaddress' => $ip, 'logtime' => self::minutesAgo($minutesAgo),
				'username' => $username, 'origin' => 0, 'handled' => $handled));
		}
	}

	private function previousBlocks($count, $ip = self::Ip)
	{
		for ($i = 0; $i < $count; ++$i)
		{
			$this->insert('#__bfstop_bannedip', array('ipaddress' => $ip,
				'crdate' => self::minutesAgo(1000 + $i), 'duration' => 60));
		}
	}

	private function createUser($username)
	{
		$id = $this->insert('#__users', array('name' => $username, 'username' => $username,
			'email' => $username.'@example.org', 'password' => '', 'registerDate' => self::minutesAgo(0),
			'params' => '{}'), 'id');
		$this->createdUsers[] = $id;
		return $id;
	}

	private function withLiveSite($liveSite, callable $test)
	{
		$app = Factory::getApplication();
		$original = $app->get('live_site', '');
		$app->set('live_site', $liveSite);
		try
		{
			return $test();
		}
		finally
		{
			$app->set('live_site', $original);
		}
	}

	public function testDefaults()
	{
		$policy = $this->policy();
		$this->assertSame('full', $policy->mode());
		$this->assertFalse($policy->isOff());
		$this->assertSame(NotifierHelper::OneDay, $policy->blockDuration());
		$this->assertSame(Settings::Defaults['checkInterval'], $policy->checkInterval());
		$this->assertSame(JPATH_ROOT, $policy->htaccessPath());
		$this->assertFalse($policy->notifiesBlockedUser());
	}

	public function testModeAndConfiguredValues()
	{
		$policy = $this->policy(array('blockMode' => 'off', 'blockDuration' => '90', 'checkInterval' => '30',
			'htaccessPath' => '/var/www/site', 'notifyBlockedUser' => '1'));
		$this->assertSame('off', $policy->mode());
		$this->assertTrue($policy->isOff());
		$this->assertSame(90, $policy->blockDuration());
		$this->assertSame(30, $policy->checkInterval());
		$this->assertSame('/var/www/site', $policy->htaccessPath());
		$this->assertTrue($policy->notifiesBlockedUser());
		$this->assertFalse($this->policy(array('blockMode' => 'htaccess'))->isOff());
	}

	public function testAnUnlimitedIntervalOrDurationIsAVeryLongOne()
	{
		$this->assertSame(BlockRepository::UnlimitedDuration, BlockPolicy::realDuration(0));
		$this->assertSame(BlockRepository::UnlimitedDuration, BlockPolicy::realDuration(-1));
		$this->assertSame(60, BlockPolicy::realDuration(60));
		$this->assertSame(BlockRepository::UnlimitedDuration, $this->policy(array('checkInterval' => 0))->checkInterval());
	}

	public function testRiskMovesTheNumberOfAllowedAttemptsButNotBelowTheMinimum()
	{
		$params = array('blockNumber' => 10, 'riskBlockNumberReductionPerPoint' => 1, 'riskMinBlockNumber' => 2);
		$policy = $this->policy($params);
		$this->assertSame(10, $policy->effectiveBlockNumber(0));
		$this->assertSame(7, $policy->effectiveBlockNumber(3), 'a suspicious attempt gets fewer');
		$this->assertSame(13, $policy->effectiveBlockNumber(-3), 'a trustworthy one more');
		$this->assertSame(2, $policy->effectiveBlockNumber(100), 'never below the minimum');
		$this->assertSame(10, $policy->effectiveBlockNumber(0.4), 'rounded');

		$this->assertSame(6, $this->policy(array('riskBlockNumberReductionPerPoint' => 2) + $params)->effectiveBlockNumber(2));
		$this->assertSame(5, $this->policy(array('riskMinBlockNumber' => 5) + $params)->effectiveBlockNumber(100));
		$this->assertSame(10, $this->policy()->effectiveBlockNumber(0), 'the default');
	}

	public function testAttemptsLeftCountsTheFailedLoginsOfTheAddressWithinTheInterval()
	{
		$policy = $this->policy(array('blockNumber' => 5, 'checkInterval' => 60,
			'riskBlockNumberReductionPerPoint' => 1, 'riskMinBlockNumber' => 1));
		$this->failedLogins(3, 10);
		$this->failedLogins(4, 120); // too long ago
		$this->failedLogins(4, 10, 'bob', '203.0.113.99'); // another address
		$this->failedLogins(4, 10, 'bob', self::Ip, 1); // handled: counted towards an earlier block
		$entry = $this->entry();

		$this->assertSame(2, $policy->attemptsLeft($entry, 0));
		$this->assertSame(0, $policy->attemptsLeft($entry, 2), 'a suspicious attempt: 3 allowed, 3 counted');
		$this->assertSame(-1, $policy->attemptsLeft($entry, 3));

		$this->failedLogins(2, 5);
		$this->assertSame(0, $policy->attemptsLeft($entry, 0), '5 allowed, 5 counted: blocked now');
	}

	public function testWithoutEarlierBlocksTheBlockHasTheConfiguredDuration()
	{
		$this->assertSame(60, $this->policy()->escalatedDuration(self::Ip, 60), 'the default maximum, no blocks yet');
		$this->previousBlocks(5, '203.0.113.99');
		$this->assertSame(60, $this->policy()->escalatedDuration(self::Ip, 60), 'the blocks of other addresses');
	}

	public function testNoEscalationIfNeitherMaximumNorProgressionAreOn()
	{
		$this->previousBlocks(10);
		$policy = $this->policy(array('maxBlocksBefore' => 0, 'progressiveBlockDuration' => 0));
		$this->assertSame(60, $policy->escalatedDuration(self::Ip, 60));
	}

	public function testBlockedForGoodAfterTheMaximumNumberOfBlocks()
	{
		$policy = $this->policy(array('maxBlocksBefore' => 3));
		$this->previousBlocks(2);
		$this->assertSame(60, $policy->escalatedDuration(self::Ip, 60));
		$this->previousBlocks(1);
		$this->assertSame(0, $policy->escalatedDuration(self::Ip, 60), '3 blocks before: permanent');
		$this->assertSame(0, $this->policy()->escalatedDuration(self::Ip, 60), 'the default maximum is 3');
	}

	public function testBlocksLiftedByAnAdministratorDoNotCountTowardsTheMaximum()
	{
		$this->previousBlocks(3);
		$this->db->setQuery("SELECT id FROM #__bfstop_bannedip WHERE ipaddress='".self::Ip."' ORDER BY id");
		$ids = $this->db->loadColumn();
		$this->insert('#__bfstop_unblock', array('block_id' => (int) $ids[0], 'source' => 0, 'crdate' => self::minutesAgo(0)));
		$this->assertSame(60, $this->policy(array('maxBlocksBefore' => 3))->escalatedDuration(self::Ip, 60));
	}

	public function testProgressiveDurationsDoubleWithEachBlockUpToSixtyFourTimes()
	{
		$policy = $this->policy(array('maxBlocksBefore' => 0, 'progressiveBlockDuration' => 1));
		$this->assertSame(60, $policy->escalatedDuration(self::Ip, 60), 'the first block');
		$expected = array(1 => 120, 2 => 240, 3 => 480, 4 => 960, 5 => 1920, 6 => 3840, 7 => 3840, 8 => 3840);
		$blocks = 0;
		foreach ($expected as $previous => $duration)
		{
			$this->previousBlocks($previous - $blocks);
			$blocks = $previous;
			$this->assertSame($duration, $policy->escalatedDuration(self::Ip, 60), "after $previous block(s)");
		}
	}

	public function testAPermanentBlockStaysPermanentWhenProgressive()
	{
		$this->previousBlocks(2);
		$policy = $this->policy(array('maxBlocksBefore' => 0, 'progressiveBlockDuration' => 1));
		$this->assertSame(0, $policy->escalatedDuration(self::Ip, 0));
	}

	public function testTheMaximumWinsOverTheProgression()
	{
		$this->previousBlocks(2);
		$policy = $this->policy(array('maxBlocksBefore' => 2, 'progressiveBlockDuration' => 1));
		$this->assertSame(0, $policy->escalatedDuration(self::Ip, 60));
		$policy = $this->policy(array('maxBlocksBefore' => 3, 'progressiveBlockDuration' => 1));
		$this->assertSame(240, $policy->escalatedDuration(self::Ip, 60));
	}

	public function testNothingIsDecidedForAnAddressWhichIsBlockedAlready()
	{
		$this->insert('#__bfstop_bannedip', array('ipaddress' => self::Ip, 'crdate' => self::minutesAgo(0), 'duration' => 60));
		$this->assertNull($this->policy()->decide($this->entry()));
		$this->assertTrue($this->logger->hasMessage(Log::INFO, 'already blocked'));
	}

	public function testTheDecisionForAnAddressWhichIsNotBlockedYet()
	{
		$decision = $this->policy(array('blockDuration' => 45))->decide($this->entry());
		$this->assertSame(array('duration' => 45, 'throughFile' => false, 'htaccess' => false,
			'htaccessEntry' => self::Ip, 'htaccessPath' => JPATH_ROOT, 'targetedOtherAccounts' => false), $decision);
	}

	public function testTheDecisionEscalatesTheDuration()
	{
		$this->previousBlocks(1);
		$decision = $this->policy(array('blockDuration' => 45, 'maxBlocksBefore' => 5, 'progressiveBlockDuration' => 1))
			->decide($this->entry());
		$this->assertSame(90, $decision['duration']);
	}

	public function testBlockingThroughTheHtaccessFile()
	{
		$decision = $this->policy(array('blockMode' => 'htaccess', 'htaccessPath' => '/var/www/site'))
			->decide($this->entry());
		$this->assertTrue($decision['throughFile']);
		$this->assertTrue($decision['htaccess']);
		$this->assertSame(self::Ip, $decision['htaccessEntry']);
		$this->assertSame('/var/www/site', $decision['htaccessPath']);
	}

	public function testAnIpv6ClientIsBlockedInTheDatabaseByItsNetworkAndInTheHtaccessFileByItsOwn64()
	{
		$entry = $this->entry('bob', '2001:db8:1::/56');
		$decision = $this->policy(array('blockMode' => 'htaccess'))->decide($entry, '2001:db8:1:2::5');
		$this->assertSame('2001:db8:1:2::/64', $decision['htaccessEntry']);
		$this->assertTrue($decision['htaccess']);
		$this->assertSame('2001:db8:1::/56', $entry->ipaddress);
	}

	public function testAnAddressWithAllowedAddressesIsOnlyBlockedInTheDatabase()
	{
		$this->insert('#__bfstop_allowlist', array('ipaddress' => '203.0.113.0/24', 'notes' => ''));
		$policy = $this->policy(array('blockMode' => 'htaccess'));
		$this->assertFalse($policy->htaccessAllowed('203.0.113.7'), 'within an allowed network');
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, '203.0.113.0/24'));
		$this->assertFalse($policy->htaccessAllowed('203.0.0.0/16'), 'containing an allowed network');
		$this->assertTrue($policy->htaccessAllowed('198.51.100.9'));

		$decision = $policy->decide($this->entry());
		$this->assertTrue($decision['throughFile']);
		$this->assertFalse($decision['htaccess'], 'a block in the file would turn away the allowed addresses');
	}

	public function testATrustedProxyIsNeverBlockedThroughTheHtaccessFile()
	{
		$this->setSettings(json_encode(array('useProxy' => 1, 'proxyIpAddress' => '198.51.100.0/24')));
		try
		{
			$policy = $this->policy(array('blockMode' => 'htaccess'));
			$this->assertFalse($policy->htaccessAllowed('198.51.100.20'), 'the proxy would turn away everybody');
			$this->assertFalse($policy->htaccessAllowed('198.51.100.0/24'), 'a network containing the proxy');
			$this->assertTrue($this->logger->hasMessage(Log::ERROR, 'trusted proxy'));
			$this->logger->errors = array(); // expected
			$this->assertTrue($policy->htaccessAllowed('203.0.113.7'));
		}
		finally
		{
			// the other tests have no trusted proxies
			if (self::$originalParams !== null)
			{
				self::storeSettings($this->db, self::$originalParams);
			}
		}
	}

	public function testBlockedUsersAreOnlyToldAboutTheirBlockIfSwitchedOn()
	{
		$this->failedLogins(2, 5, 'alice');
		$this->createUser('alice');
		$entry = $this->entry('bob');
		$params = array('checkInterval' => 60);

		$off = $this->policy($params)->decide($entry);
		$this->assertFalse($off['targetedOtherAccounts'], 'not looked at if no mail can go out');

		$on = $this->policy(array('notifyBlockedUser' => 1) + $params)->decide($entry);
		$this->assertTrue($on['targetedOtherAccounts'], 'the failed logins also went against the account alice');
	}

	public function testFailedLoginsAgainstOtherUsernamesWhichAreNoAccountsDoNotCount()
	{
		$this->failedLogins(2, 5, 'nobody');
		$this->failedLogins(1, 5, 'BOB');
		$decision = $this->policy(array('notifyBlockedUser' => 1, 'checkInterval' => 60))->decide($this->entry('bob'));
		$this->assertFalse($decision['targetedOtherAccounts']);
	}

	public function testNoUnblockMailIfTheFailedLoginsAlsoWentAgainstOtherAccounts()
	{
		$policy = $this->policy(array('notifyBlockedUser' => 2));
		$why = $this->withLiveSite('https://www.example.org', function () use ($policy)
		{
			return $policy->whyNoUnblockMail($this->entry(), null, true);
		});
		$this->assertStringContainsString('other accounts', $why);
	}

	public function testNoUnblockMailWithoutTheAddressOfTheSite()
	{
		foreach (array(1, 2) as $mode)
		{
			$policy = $this->policy(array('notifyBlockedUser' => $mode));
			$why = $this->withLiveSite('', function () use ($policy)
			{
				return $policy->whyNoUnblockMail($this->entry(), null, false);
			});
			$this->assertStringContainsString('$live_site', (string) $why, "mode $mode");
		}
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, '$live_site'));
	}

	public function testOnlyOneUsableUnblockMailAtATimeForAnyAddress()
	{
		$policy = $this->policy(array('notifyBlockedUser' => BlockPolicy::NotifyBlockedAnyAddress));
		$ask = function () use ($policy)
		{
			return $this->withLiveSite('https://www.example.org', function () use ($policy)
			{
				return $policy->whyNoUnblockMail($this->entry('Bob'), null, false);
			});
		};
		$this->assertNull($ask());
		$blockId = $this->insert('#__bfstop_bannedip', array('ipaddress' => self::Ip, 'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		$this->repos->unblockTokens()->add($blockId, 'sometoken', 'bob');
		$this->assertStringContainsString('already', (string) $ask(), 'whatever the case of the username');
	}

	public function testUnblockMailsForKnownAddressesGoToUsersWhoLoggedInFromThere()
	{
		$policy = $this->policy(array('notifyBlockedUser' => BlockPolicy::NotifyBlockedKnownAddress));
		$ask = function ($username, $client = null) use ($policy)
		{
			return $this->withLiveSite('https://www.example.org', function () use ($policy, $username, $client)
			{
				return $policy->whyNoUnblockMail($this->entry($username), $client, false);
			});
		};
		$this->assertStringContainsString('never logged in', (string) $ask('bob'));
		$this->repos->knownIps()->remember(self::Ip, 'bob');
		$this->assertNull($ask('bob'));
		$this->assertNull($ask('BOB'), 'whatever the case');
		$this->assertStringContainsString('never logged in', (string) $ask('alice'), 'another user');
		$this->assertStringContainsString('never logged in', (string) $ask('bob', '203.0.113.200'), 'another client address');
	}

	public function testTheSettingOnlyTakesEffectWithTheAddressOfTheSite()
	{
		$this->assertSame(BlockPolicy::NotifyBlockedAnyAddress, BlockPolicy::effectiveNotifyBlockedUser('2', true));
		$this->assertSame(0, BlockPolicy::effectiveNotifyBlockedUser(2, false));
		$this->assertTrue($this->withLiveSite('https://www.example.org', function () { return BlockPolicy::hasLiveSite(); }));
		$this->assertFalse($this->withLiveSite('  ', function () { return BlockPolicy::hasLiveSite(); }));
	}

	public function testTheDelayIsTheBaseDelayPlusOneSecondPerPointOfPositiveRisk()
	{
		$policy = $this->policy(array('delayDuration' => 3, 'riskDelaySecondsPerPoint' => 2, 'accountThrottleEnabled' => 0));
		$entry = $this->entry();
		$this->assertEquals(3, $policy->delaySeconds($entry, 0));
		$this->assertEquals(7, $policy->delaySeconds($entry, 2));
		$this->assertEquals(3, $policy->delaySeconds($entry, -5), 'trust never reduces the delay');
		$this->assertEquals(0, $this->policy(array('accountThrottleEnabled' => 0))->delaySeconds($entry, 10), 'no delay by default');
	}

	public function testTheAccountThrottleAddsDelayOnceEnoughFailedLoginsAimedAtTheUsername()
	{
		$params = array('accountThrottleEnabled' => 1, 'accountCheckInterval' => 60,
			'accountBlockNumber' => 3, 'accountThrottleDelay' => 5, 'riskDelaySecondsPerPoint' => 0);
		$entry = $this->entry('bob');
		// from any address; not the ones of another account, nor too old, nor handled already
		$this->failedLogins(1, 5, 'bob', '203.0.113.1');
		$this->failedLogins(1, 5, 'bob', '203.0.113.2');
		$this->failedLogins(5, 5, 'carol', '203.0.113.3');
		$this->failedLogins(5, 120, 'bob', '203.0.113.4');
		$this->failedLogins(5, 5, 'bob', '203.0.113.5', 1);
		$this->assertEquals(0, $this->policy($params)->delaySeconds($entry, 0), '2 of 3');

		$this->failedLogins(1, 5, 'bob', '203.0.113.6');
		$this->assertEquals(5, $this->policy($params)->delaySeconds($entry, 0), '3 of 3');
		$this->assertEquals(0, $this->policy($params)->delaySeconds($this->entry('dave'), 0), 'another account');
		$this->assertEquals(0, $this->policy(array('accountThrottleEnabled' => 0) + $params)->delaySeconds($entry, 0), 'switched off');
		$this->assertEquals(0, $this->policy(array('accountThrottleDelay' => 0) + $params)->delaySeconds($entry, 0));
		$this->assertEquals(0, $this->policy(array('accountThrottleDelay' => -3) + $params)->delaySeconds($entry, 0), 'never negative');
		$this->assertEquals(5 + 4, $this->policy(array('delayDuration' => 4) + $params)->delaySeconds($entry, 0), 'adds to the base delay');
	}

	public function testTheAdaptiveDelayGrowsWithTheFailedLoginsOfTheLastHour()
	{
		$params = array('accountThrottleEnabled' => 0, 'adaptiveDelay' => 1, 'delayDuration' => 1,
			'adaptiveDelayMax' => 11, 'adaptiveDelayThresholdMin' => 10, 'adaptiveDelayThresholdMax' => 20);
		$entry = $this->entry();
		$this->failedLogins(5, 10, 'x');
		$this->assertEquals(1, $this->policy($params)->delaySeconds($entry, 0), 'below the lower threshold');
		$this->failedLogins(10, 10, 'x'); // 15
		$this->assertEquals(6, $this->policy($params)->delaySeconds($entry, 0), 'halfway between the thresholds');
		$this->failedLogins(15, 10, 'x'); // 30
		$this->assertEquals(11, $this->policy($params)->delaySeconds($entry, 0), 'capped at the maximum');
		$this->assertEquals(1, $this->policy(array('adaptiveDelay' => 0) + $params)->delaySeconds($entry, 0), 'switched off');
		$this->assertEquals(11 + 6, $this->policy(array('riskDelaySecondsPerPoint' => 2) + $params)->delaySeconds($entry, 3),
			'plus the delay for the risk');
	}

	public function testThresholdsOfTheAdaptiveDelayInTheWrongOrderAreSwapped()
	{
		$params = array('accountThrottleEnabled' => 0, 'adaptiveDelay' => 1, 'delayDuration' => 1,
			'adaptiveDelayMax' => 11, 'adaptiveDelayThresholdMin' => 20, 'adaptiveDelayThresholdMax' => 10);
		$this->failedLogins(15, 10, 'x');
		$this->assertEquals(6, $this->policy($params)->delaySeconds($this->entry(), 0));
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, 'Swapping'));
	}

	public function testEqualThresholdsOfTheAdaptiveDelayFallBackToTheBaseDelay()
	{
		$params = array('accountThrottleEnabled' => 0, 'adaptiveDelay' => 1, 'delayDuration' => 2,
			'adaptiveDelayMax' => 11, 'adaptiveDelayThresholdMin' => 10, 'adaptiveDelayThresholdMax' => 10);
		$this->failedLogins(30, 10, 'x');
		$this->assertEquals(2, $this->policy($params)->delaySeconds($this->entry(), 0));
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, 'cannot be configured to the same value'));
	}
}
