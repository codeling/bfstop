<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Repository\DnsCacheRepository;
use Codeling\Library\Bfstop\Repository\FailedLoginRepository;
use Codeling\Library\Bfstop\Repository\KnownIpRepository;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\LoginService;
use Codeling\Library\Bfstop\Helper\RiskHelper;
use Joomla\CMS\Log\Log;
use Joomla\Registry\Registry;

class RiskHelperTest extends IntegrationTestCase
{
	private array $serverBackup;

	protected function setUp(): void
	{
		parent::setUp();
		$this->serverBackup = $_SERVER;
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (X11; Linux x86_64)';
	}

	protected function tearDown(): void
	{
		$_SERVER = $this->serverBackup;
	}

	/**
	 * All signals which are on by default switched off, so that each test
	 * can enable exactly the one it is interested in.
	 */
	private static function allOff(array $overrides = array())
	{
		return new Registry(array_merge(array(
			'riskKnownIpEnabled'        => 0,
			'riskCommonUsernameEnabled' => 0,
			'riskUserAgentEnabled'      => 0,
			'riskGeoEnabled'            => 0,
			'riskReverseDnsEnabled'     => 0,
			'accountAttackEnabled'      => 0,
		), $overrides));
	}

	/** the repositories of the signals, as the given mocks (or mocks which answer nothing) */
	private function repos($known = null, $dns = null)
	{
		$repos = $this->createMock(Repositories::class);
		$repos->method('knownIps')->willReturn($known ?? $this->createMock(KnownIpRepository::class));
		$repos->method('dnsCache')->willReturn($dns ?? $this->createMock(DnsCacheRepository::class));
		return $repos;
	}

	private function db($knownIp = false)
	{
		$known = $this->createMock(KnownIpRepository::class);
		$known->method('hasLoggedInFrom')->willReturn($knownIp);
		return $this->repos($known);
	}

	public function testAllSignalsDisabledScoresZero()
	{
		$known = $this->createMock(KnownIpRepository::class);
		$known->expects($this->never())->method('hasLoggedInFrom');
		$dns = $this->createMock(DnsCacheRepository::class);
		$dns->expects($this->never())->method('get');
		$db = $this->repos($known, $dns);
		$_SERVER['HTTP_USER_AGENT'] = '';
		$this->assertSame(0, RiskHelper::computeScore($db, $this->logger, self::allOff(), '203.0.113.5', 'admin'));
	}

	public function testDefaultsWithTrustworthyRequestScoreZero()
	{
		// defaults: known-IP, common-username and user-agent signals on; geo and rDNS off
		$params = new Registry(array('riskCommonUsernames' => "admin\nroot"));
		$this->assertSame(0, RiskHelper::computeScore($this->db(false), $this->logger, $params, '203.0.113.5', 'jdoe'));
	}

	public function testKnownIpReducesScore()
	{
		$params = self::allOff(array('riskKnownIpEnabled' => 1));
		$this->assertSame(-5, RiskHelper::computeScore($this->db(true), $this->logger, $params, '203.0.113.5', 'jdoe'));
		$params->set('riskKnownIpPoints', 8);
		$this->assertSame(-8, RiskHelper::computeScore($this->db(true), $this->logger, $params, '203.0.113.5', 'jdoe'));
		$this->assertSame(0, RiskHelper::computeScore($this->db(false), $this->logger, $params, '203.0.113.5', 'jdoe'));
	}

	public function testKnownIpLookupFailureFailsSafe()
	{
		$known = $this->createMock(KnownIpRepository::class);
		$known->method('hasLoggedInFrom')->willThrowException(new \RuntimeException('db down'));
		$db = $this->repos($known);
		$logger = $this->logger;
		$params = self::allOff(array('riskKnownIpEnabled' => 1));
		$this->assertSame(0, RiskHelper::computeScore($db, $logger, $params, '203.0.113.5', 'jdoe'));
		$this->assertTrue($logger->hasMessage(Log::WARNING, 'db down'));
	}

	public function testCommonUsernameMatchesCaseInsensitivelyWithCrlfList()
	{
		$params = self::allOff(array('riskCommonUsernameEnabled' => 1,
			'riskCommonUsernames' => "admin\r\n  Root  \r\n\r\ntest"));
		$logger = $this->logger;
		$this->assertSame(2, RiskHelper::computeScore($this->db(), $logger, $params, '203.0.113.5', 'ADMIN'));
		$this->assertSame(2, RiskHelper::computeScore($this->db(), $logger, $params, '203.0.113.5', 'root'));
		$this->assertSame(0, RiskHelper::computeScore($this->db(), $logger, $params, '203.0.113.5', 'administrator'));
		$this->assertSame(0, RiskHelper::computeScore($this->db(), $logger, $params, '203.0.113.5', ''));
		$params->set('riskCommonUsernamePoints', 4);
		$this->assertSame(4, RiskHelper::computeScore($this->db(), $logger, $params, '203.0.113.5', 'test'));
	}

	public function testMissingUserAgentIncreasesScore()
	{
		$params = self::allOff(array('riskUserAgentEnabled' => 1));
		$logger = $this->logger;
		$this->assertSame(0, RiskHelper::computeScore($this->db(), $logger, $params, '203.0.113.5', 'jdoe'));
		$_SERVER['HTTP_USER_AGENT'] = '   ';
		$this->assertSame(2, RiskHelper::computeScore($this->db(), $logger, $params, '203.0.113.5', 'jdoe'));
		unset($_SERVER['HTTP_USER_AGENT']);
		$this->assertSame(2, RiskHelper::computeScore($this->db(), $logger, $params, '203.0.113.5', 'jdoe'));
	}

	public function testGeoWithoutDatabaseScoresZero()
	{
		$params = self::allOff(array('riskGeoEnabled' => 1, 'geoDbPath' => '', 'riskGeoHomeCountries' => 'AT,DE'));
		$this->assertSame(0, RiskHelper::computeScore($this->db(), $this->logger, $params, '203.0.113.5', 'jdoe'));
	}

	public function testReverseDnsUsesCachedHostname()
	{
		$params = self::allOff(array('riskReverseDnsEnabled' => 1));

		$dns = $this->createMock(DnsCacheRepository::class);
		$dns->method('get')->willReturn('host.example.org');
		$dns->expects($this->never())->method('put');
		$db = $this->repos(null, $dns);
		$this->assertSame(0, RiskHelper::computeScore($db, $this->logger, $params, '203.0.113.5', 'jdoe'));

		$dns = $this->createMock(DnsCacheRepository::class);
		$dns->method('get')->willReturn(null); // cached "no PTR record"
		$dns->expects($this->never())->method('put');
		$db = $this->repos(null, $dns);
		$this->assertSame(2, RiskHelper::computeScore($db, $this->logger, $params, '203.0.113.5', 'jdoe'));
	}

	public function testReverseDnsIsCachedByTheTrackedNetwork()
	{
		// an IPv6 client switching addresses would otherwise miss the cache,
		// and cause a lookup, with every failed login
		$params = self::allOff(array('riskReverseDnsEnabled' => 1));
		$dns = $this->createMock(DnsCacheRepository::class);
		$dns->expects($this->once())->method('get')->with('2001:db8:1::/56')->willReturn('host.example.org');
		$db = $this->repos(null, $dns);
		$this->assertSame(0, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:2::5', 'jdoe', '2001:db8:1::/56'));
	}

	public function testReverseDnsLookupIsLimitedInTime()
	{
		// a documentation address has no PTR record: whether the name
		// servers of /etc/resolv.conf say so or can't be reached, the result
		// is "no record", within DnsHelper::TimeoutSeconds, and is cached
		if (\Codeling\Library\Bfstop\Helper\DnsHelper::nameservers() === array())
		{
			$this->markTestSkipped('no name server in /etc/resolv.conf');
		}
		$params = self::allOff(array('riskReverseDnsEnabled' => 1));
		$dns = $this->createMock(DnsCacheRepository::class);
		$dns->method('get')->willReturn(false);
		$dns->expects($this->once())->method('put')->with('2001:db8:1::/56', null);
		$db = $this->repos(null, $dns);
		$start = microtime(true);
		$this->assertSame(2, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:2::5', 'jdoe', '2001:db8:1::/56'));
		$this->assertLessThan(\Codeling\Library\Bfstop\Helper\DnsHelper::TimeoutSeconds + 0.5, microtime(true) - $start);
	}

	public function testReverseDnsFailureFailsSafe()
	{
		$params = self::allOff(array('riskReverseDnsEnabled' => 1));
		$dns = $this->createMock(DnsCacheRepository::class);
		$dns->method('get')->willThrowException(new \RuntimeException('cache broken'));
		$db = $this->repos(null, $dns);
		$logger = $this->logger;
		$this->assertSame(0, RiskHelper::computeScore($db, $logger, $params, '203.0.113.5', 'jdoe'));
		$this->assertTrue($logger->hasMessage(Log::WARNING, 'cache broken'));
	}

	public function testSignalsAreSummed()
	{
		$params = new Registry(array(
			'riskCommonUsernames'   => 'admin',
			'riskReverseDnsEnabled' => 1,
		));
		$known = $this->createMock(KnownIpRepository::class);
		$known->method('hasLoggedInFrom')->willReturn(true);
		$dns = $this->createMock(DnsCacheRepository::class);
		$dns->method('get')->willReturn(null);
		$db = $this->repos($known, $dns);
		unset($_SERVER['HTTP_USER_AGENT']);
		// known IP -5, common username +2, no user agent +2, no rDNS +2
		$this->assertSame(1, RiskHelper::computeScore($db, $this->logger, $params, '203.0.113.5', 'admin'));
	}

	public function testKnownIpScoreRecognisesTheNetworkOfAnIpv6Client()
	{
		// logins are remembered by network (see LoginService::recordSuccessfulLogin()),
		// so an IPv6 client switching addresses is still a known one
		$db = new Repositories($this->logger);
		(new LoginService($db))->recordSuccessfulLogin((object) array('ipaddress' => '2001:db8:1:2::5', 'username' => 'bob'), '2001:db8:1:2::/64');
		$params = self::allOff(array('riskKnownIpEnabled' => 1, 'riskKnownIpPoints' => 5));
		$this->assertSame(-5, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:2:aaaa::9', 'bob'));
		$this->assertSame(0, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:3::9', 'bob'), 'another network');
		$this->assertSame(0, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:2:aaaa::9', 'eve'), 'another user');
	}

	public function testKnownIpScoreHonoursTheConfiguredNetworkSize()
	{
		$db = new Repositories($this->logger);
		(new LoginService($db))->recordSuccessfulLogin((object) array('ipaddress' => '2001:db8:1:2::5', 'username' => 'bob'), '2001:db8:1:2::5');
		$params = self::allOff(array('riskKnownIpEnabled' => 1, 'riskKnownIpPoints' => 5, 'ipv6PrefixLength' => 128));
		$this->assertSame(-5, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:2::5', 'bob'));
		$this->assertSame(0, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:2::6', 'bob'));
	}

	public function testTheAccountAttackSignalCountsTheUsernameAsStored()
	{
		// the hash of a username which is no account, not what was typed
		$failed = $this->createMock(FailedLoginRepository::class);
		$failed->expects($this->once())->method('countUnhandledForUsername')
			->with(30, 'h:0123abcd', '2026-01-02 03:04:05')->willReturn(7);
		$repos = $this->repos();
		$repos->method('failedLogins')->willReturn($failed);
		$params = self::allOff(array('accountAttackEnabled' => 1, 'accountCheckInterval' => 30,
			'accountBlockNumber' => 7, 'accountAttackPoints' => 3));
		$entry = (object) array('username' => 'h:0123abcd', 'logtime' => '2026-01-02 03:04:05');
		$this->assertSame(3, RiskHelper::computeScore($repos, $this->logger, $params, '203.0.113.5', 'jdoe', null, $entry));
	}

	public function testTheAccountAttackSignalFailsSafe()
	{
		$failed = $this->createMock(FailedLoginRepository::class);
		$failed->method('countUnhandledForUsername')->willThrowException(new \RuntimeException('table gone'));
		$repos = $this->repos();
		$repos->method('failedLogins')->willReturn($failed);
		$params = self::allOff(array('accountAttackEnabled' => 1, 'accountBlockNumber' => 1));
		$entry = (object) array('username' => 'jdoe', 'logtime' => '2026-01-02 03:04:05');
		$this->assertSame(0, RiskHelper::computeScore($repos, $this->logger, $params, '203.0.113.5', 'jdoe', null, $entry));
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, 'table gone'));
	}
}
