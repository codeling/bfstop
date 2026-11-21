<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Helper\LockHelper;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\PluginHelper;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * IpHelper::getAddress() with the proxy settings read from the plugin's
 * params: a forwarding header may only be trusted if the request actually
 * comes from the configured proxy, otherwise any visitor could make their
 * failed logins count against an arbitrary other IP address.
 */
class IpHelperAddressTest extends IntegrationTestCase
{
	private static $originalParams;
	private $serverBackup;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		$db = \Joomla\CMS\Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
		$db->setQuery("SELECT params FROM #__extensions WHERE type='component' AND element='com_bfstop'");
		self::$originalParams = $db->loadResult();
	}

	public static function tearDownAfterClass(): void
	{
		if (self::$originalParams !== null)
		{
			$db = \Joomla\CMS\Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
			self::storeSettings($db, self::$originalParams);
			self::forgetPlugins();
		}
	}

	private static function forgetPlugins()
	{
		(new \ReflectionProperty(PluginHelper::class, 'plugins'))->setValue(null, null);
	}

	protected function setUp(): void
	{
		parent::setUp();
		$this->serverBackup = $_SERVER;
		$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
		foreach (IpHelper::KnownProxyHeaders as $header)
		{
			unset($_SERVER[$header]);
		}
		// no warning about a request which bypassed the proxy was logged yet
		self::forgetDirectRequestWarnings();
	}

	private static function forgetDirectRequestWarnings()
	{
		foreach (glob(LockHelper::file('proxywarning', '*', 'stamp')) ?: array() as $file)
		{
			@unlink($file);
		}
	}

	protected function tearDown(): void
	{
		$_SERVER = $this->serverBackup;
	}

	private function configure(array $params)
	{
		$this->setSettings(json_encode($params));
		self::forgetPlugins();
	}

	public function testProxyDisabledIgnoresHeader()
	{
		$this->configure(array('useProxy' => 0, 'proxyIpAddress' => '198.51.100.7'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';
		$this->assertSame('198.51.100.7', IpHelper::getAddress($this->logger));
	}

	public function testIpv4MappedAddressesAreIpv4()
	{
		// a web server listening on an IPv6 socket which takes IPv4
		// connections too reports an IPv4 client as ::ffff:a.b.c.d
		$this->configure(array('useProxy' => 0));
		$_SERVER['REMOTE_ADDR'] = '::ffff:203.0.113.5';
		$this->assertSame('203.0.113.5', IpHelper::getAddress($this->logger));
		// the proxy as well as the client behind it
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '198.51.100.7'));
		$_SERVER['REMOTE_ADDR'] = '::ffff:198.51.100.7';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, ::ffff:203.0.113.6';
		$this->assertSame('203.0.113.6', IpHelper::getAddress($this->logger));
	}

	public function testProxyEnabledButRequestNotFromProxyIgnoresHeader()
	{
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '192.0.2.1'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';
		$this->assertSame('198.51.100.7', IpHelper::getAddress($this->logger));
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, 'did not originate from the configured proxy'));
	}

	public function testRequestsBypassingTheProxyAreWarnedAboutOnceAnHour()
	{
		// anybody can send them: a warning for each would push the entries
		// that matter out of the rotated log
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '192.0.2.1'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';
		$this->assertSame('198.51.100.7', IpHelper::getAddress($this->logger));
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, 'did not originate from the configured proxy'));
		$this->assertFileExists(IpHelper::directRequestWarningFile('198.51.100.7'));

		// the next request of the address (another one: the address of a
		// request is worked out once) is not logged again ...
		$this->logger->messages = array();
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.6';
		$this->assertSame('198.51.100.7', IpHelper::getAddress($this->logger));
		$this->assertFalse($this->logger->hasMessage(Log::WARNING, 'did not originate from the configured proxy'));

		// ... but an address of another stamp is
		$other = null;
		for ($i = 1; $i < 255 && $other === null; ++$i)
		{
			$candidate = '198.51.100.'.(100 + $i % 150);
			if (IpHelper::directRequestWarningFile($candidate) !== IpHelper::directRequestWarningFile('198.51.100.7'))
			{
				$other = $candidate;
			}
		}
		$_SERVER['REMOTE_ADDR'] = $other;
		$this->assertSame($other, IpHelper::getAddress($this->logger));
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, 'actual: "'.$other.'"'));

		// and the first address once the hour is over
		$this->logger->messages = array();
		touch(IpHelper::directRequestWarningFile('198.51.100.7'), time() - IpHelper::DirectRequestWarningInterval);
		$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
		$this->assertSame('198.51.100.7', IpHelper::getAddress($this->logger));
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, 'did not originate from the configured proxy'));
	}

	public function testProxyEnabledWithoutConfiguredProxyIpIgnoresHeader()
	{
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => ''));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';
		$this->assertSame('198.51.100.7', IpHelper::getAddress($this->logger));
		$this->assertTrue($this->logger->hasMessage(Log::WARNING));
	}

	public static function trustedProxyHeaderProvider()
	{
		return array(
			'single public IP'        => array('203.0.113.5', '203.0.113.5'),
			'last entry wins'         => array('203.0.113.5, 198.51.100.9', '198.51.100.9'),
			'forged leftmost entry'   => array('1.2.3.4, 203.0.113.5', '203.0.113.5'),
			'private client'          => array('203.0.113.5, 10.0.0.9', '10.0.0.9'),
			'whitespace is trimmed'   => array('   203.0.113.5   ', '203.0.113.5'),
			'public IPv6'             => array('fd00::1, 2001:4860:4860::8888', '2001:4860:4860::8888'),
			'trusted proxy hop'       => array('203.0.113.5, 198.51.100.7', '203.0.113.5'),
		);
	}

	#[DataProvider('trustedProxyHeaderProvider')]
	public function testTrustedProxyUsesRightmostNonProxyAddress($header, $expected)
	{
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '198.51.100.7'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = $header;
		$this->assertSame($expected, IpHelper::getAddress($this->logger));
	}

	public function testTrustedProxyListAndSubnets()
	{
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '192.0.2.1, 198.51.100.0/24'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 203.0.113.5, 192.0.2.1';
		$this->assertSame('203.0.113.5', IpHelper::getAddress($this->logger));
	}

	public function testGarbageAsLastEntryFallsBack()
	{
		// nothing to the left of it can be trusted
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '198.51.100.7'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5, not-an-ip';
		$this->assertSame('198.51.100.7', IpHelper::getAddress($this->logger));
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, 'falling back to REMOTE_ADDR'));
	}

	public function testHeaderOfOnlyTrustedProxiesFallsBack()
	{
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '198.51.100.7'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.7';
		$this->assertSame('198.51.100.7', IpHelper::getAddress($this->logger));
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, 'falling back to REMOTE_ADDR'));
	}

	public function testConfiguredHeaderSourceIsHonoured()
	{
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '198.51.100.7', 'proxyHeaderSource' => 'HTTP_CLIENT_IP'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';
		$_SERVER['HTTP_CLIENT_IP'] = '203.0.113.77';
		$this->assertSame('203.0.113.77', IpHelper::getAddress($this->logger));
	}

	public function testWorkedOutOnceForTheSameRequest()
	{
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '198.51.100.7'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5, not-an-ip';
		$warnings = function ()
		{
			return count(array_filter($this->logger->messages, function ($m)
			{
				return $m['priority'] === Log::WARNING;
			}));
		};
		$this->assertSame('198.51.100.7', IpHelper::getAddress($this->logger));
		$this->assertSame('198.51.100.7', IpHelper::getAddress($this->logger));
		$this->assertSame(1, $warnings(), 'the plugin and the component ask several times: warned once');

		// another header, another REMOTE_ADDR, other settings: worked out again
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';
		$this->assertSame('203.0.113.5', IpHelper::getAddress($this->logger));
		$_SERVER['REMOTE_ADDR'] = '192.0.2.99';
		$this->assertSame('192.0.2.99', IpHelper::getAddress($this->logger));
		$this->assertSame(2, $warnings(), 'not from the proxy');
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '192.0.2.99'));
		$this->assertSame('203.0.113.5', IpHelper::getAddress($this->logger));
		$this->configure(array('useProxy' => 0));
		$this->assertSame('192.0.2.99', IpHelper::getAddress($this->logger));
	}
}
