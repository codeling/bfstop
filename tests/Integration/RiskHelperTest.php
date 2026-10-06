<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Codeling\Plugin\System\Bfstop\Helper\RiskHelper;
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
		), $overrides));
	}

	private function db($knownIp = false)
	{
		$db = $this->createMock(DatabaseHelper::class);
		$db->method('hasLoggedInFrom')->willReturn($knownIp);
		return $db;
	}

	public function testAllSignalsDisabledScoresZero()
	{
		$db = $this->createMock(DatabaseHelper::class);
		$db->expects($this->never())->method('hasLoggedInFrom');
		$db->expects($this->never())->method('getCachedHostname');
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
		$db = $this->createMock(DatabaseHelper::class);
		$db->method('hasLoggedInFrom')->willThrowException(new \RuntimeException('db down'));
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

		$db = $this->createMock(DatabaseHelper::class);
		$db->method('getCachedHostname')->willReturn('host.example.org');
		$db->expects($this->never())->method('cacheHostname');
		$this->assertSame(0, RiskHelper::computeScore($db, $this->logger, $params, '203.0.113.5', 'jdoe'));

		$db = $this->createMock(DatabaseHelper::class);
		$db->method('getCachedHostname')->willReturn(null); // cached "no PTR record"
		$db->expects($this->never())->method('cacheHostname');
		$this->assertSame(2, RiskHelper::computeScore($db, $this->logger, $params, '203.0.113.5', 'jdoe'));
	}

	public function testReverseDnsFailureFailsSafe()
	{
		$params = self::allOff(array('riskReverseDnsEnabled' => 1));
		$db = $this->createMock(DatabaseHelper::class);
		$db->method('getCachedHostname')->willThrowException(new \RuntimeException('cache broken'));
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
		$db = $this->createMock(DatabaseHelper::class);
		$db->method('hasLoggedInFrom')->willReturn(true);
		$db->method('getCachedHostname')->willReturn(null);
		unset($_SERVER['HTTP_USER_AGENT']);
		// known IP -5, common username +2, no user agent +2, no rDNS +2
		$this->assertSame(1, RiskHelper::computeScore($db, $this->logger, $params, '203.0.113.5', 'admin'));
	}

	public function testKnownIpScoreRecognisesTheNetworkOfAnIpv6Client()
	{
		// logins are remembered by network (see DatabaseHelper::successfulLogin()),
		// so an IPv6 client switching addresses is still a known one
		$db = new DatabaseHelper($this->logger);
		$db->successfulLogin((object) array('ipaddress' => '2001:db8:1:2::5', 'username' => 'bob'), '2001:db8:1:2::/64');
		$params = self::allOff(array('riskKnownIpEnabled' => 1, 'riskKnownIpPoints' => 5));
		$this->assertSame(-5, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:2:aaaa::9', 'bob'));
		$this->assertSame(0, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:3::9', 'bob'), 'another network');
		$this->assertSame(0, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:2:aaaa::9', 'eve'), 'another user');
	}

	public function testKnownIpScoreHonoursTheConfiguredNetworkSize()
	{
		$db = new DatabaseHelper($this->logger);
		$db->successfulLogin((object) array('ipaddress' => '2001:db8:1:2::5', 'username' => 'bob'), '2001:db8:1:2::5');
		$params = self::allOff(array('riskKnownIpEnabled' => 1, 'riskKnownIpPoints' => 5, 'ipv6PrefixLength' => 128));
		$this->assertSame(-5, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:2::5', 'bob'));
		$this->assertSame(0, RiskHelper::computeScore($db, $this->logger, $params, '2001:db8:1:2::6', 'bob'));
	}
}
