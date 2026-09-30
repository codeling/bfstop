<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
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
		$db = \Joomla\CMS\Factory::getDbo();
		$db->setQuery("SELECT params FROM #__extensions WHERE type='plugin' AND element='bfstop'");
		self::$originalParams = $db->loadResult();
	}

	public static function tearDownAfterClass(): void
	{
		if (self::$originalParams !== null)
		{
			$db = \Joomla\CMS\Factory::getDbo();
			$db->setQuery('UPDATE #__extensions SET params='.$db->quote(self::$originalParams).
				" WHERE type='plugin' AND element='bfstop'");
			$db->execute();
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
	}

	protected function tearDown(): void
	{
		$_SERVER = $this->serverBackup;
	}

	private function configure(array $params)
	{
		$this->setPluginParams(json_encode($params));
		self::forgetPlugins();
	}

	public function testProxyDisabledIgnoresHeader()
	{
		$this->configure(array('useProxy' => 0, 'proxyIpAddress' => '198.51.100.7'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';
		$this->assertSame('198.51.100.7', IpHelper::getAddress($this->logger));
	}

	public function testProxyEnabledButRequestNotFromProxyIgnoresHeader()
	{
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '192.0.2.1'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';
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
			'first public in list'    => array('203.0.113.5, 198.51.100.9', '203.0.113.5'),
			'skips private'           => array('10.0.0.1, 192.168.1.1, 203.0.113.5', '203.0.113.5'),
			'skips loopback/reserved' => array('127.0.0.1,0.0.0.0, 203.0.113.5', '203.0.113.5'),
			'whitespace is trimmed'   => array('   203.0.113.5   ', '203.0.113.5'),
			'garbage is skipped'      => array('not-an-ip, 203.0.113.5', '203.0.113.5'),
			'public IPv6'             => array('fd00::1, 2001:4860:4860::8888', '2001:4860:4860::8888'),
		);
	}

	#[DataProvider('trustedProxyHeaderProvider')]
	public function testTrustedProxyUsesFirstPublicIpFromHeader($header, $expected)
	{
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '198.51.100.7'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = $header;
		$this->assertSame($expected, IpHelper::getAddress($this->logger));
	}

	public function testTrustedProxyWithOnlyPrivateAddressesFallsBack()
	{
		$this->configure(array('useProxy' => 1, 'proxyIpAddress' => '198.51.100.7'));
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '10.1.2.3, 172.16.0.1';
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
}
