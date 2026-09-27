<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// run with: phpunit unittests/subnettest.php
use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use PHPUnit\Framework\TestCase;

if (!defined('_JEXEC'))
{
	define('_JEXEC', 1);
}
require_once(__DIR__.'/../src/Helper/IpHelper.php');

class IpHelperSubnetTest extends TestCase
{
	public function testIPv4()
	{
		$this->assertTrue(IpHelper::isInSubnet('198.51.100.200', '198.51.100.0/24'));
		$this->assertFalse(IpHelper::isInSubnet('198.51.101.1', '198.51.100.0/24'));
		$this->assertTrue(IpHelper::isInSubnet('203.0.113.5', '203.0.113.4/31'));
		$this->assertFalse(IpHelper::isInSubnet('203.0.113.6', '203.0.113.4/31'));
		$this->assertTrue(IpHelper::isInSubnet('203.0.113.5', '203.0.113.5/32'));
		$this->assertFalse(IpHelper::isInSubnet('203.0.113.6', '203.0.113.5/32'));
		$this->assertTrue(IpHelper::isInSubnet('192.0.2.1', '0.0.0.0/0'));
		// subnet address not aligned to the prefix length
		$this->assertTrue(IpHelper::isInSubnet('198.51.100.7', '198.51.100.99/24'));
	}

	public function testIPv6()
	{
		$this->assertTrue(IpHelper::isInSubnet('2001:db8:ab:1::5', '2001:DB8:AB::/48'));
		$this->assertFalse(IpHelper::isInSubnet('2001:db8:ac::1', '2001:db8:ab::/48'));
		$this->assertTrue(IpHelper::isInSubnet('2001:db8::1', '2001:db8::/32'));
		$this->assertTrue(IpHelper::isInSubnet('2001:db8::1', '2001:db8::1/128'));
		$this->assertFalse(IpHelper::isInSubnet('2001:db8::2', '2001:db8::1/128'));
		$this->assertTrue(IpHelper::isInSubnet('2001:db8:0:7fff::1', '2001:db8::/49'));
		$this->assertFalse(IpHelper::isInSubnet('2001:db8:0:8000::1', '2001:db8::/49'));
	}

	public function testMalformedNeverMatches()
	{
		// prefix length out of range, not a number, missing, or too long
		$this->assertFalse(IpHelper::isInSubnet('192.0.2.1', '192.0.2.0/33'));
		$this->assertFalse(IpHelper::isInSubnet('192.0.2.1', '192.0.2.0/99'));
		$this->assertFalse(IpHelper::isInSubnet('192.0.2.1', '192.0.2.0/abc'));
		$this->assertFalse(IpHelper::isInSubnet('192.0.2.1', '192.0.2.0/'));
		$this->assertFalse(IpHelper::isInSubnet('192.0.2.1', '192.0.2.0/-1'));
		$this->assertFalse(IpHelper::isInSubnet('192.0.2.1', '192.0.2.0/0024'));
		$this->assertFalse(IpHelper::isInSubnet('2001:db8::1', '2001:db8::/129'));
		$this->assertFalse(IpHelper::isInSubnet('192.0.2.1', '192.0.2.0'));
		$this->assertFalse(IpHelper::isInSubnet('192.0.2.1', '192.0.2.0/24/8'));
		// unparseable addresses
		$this->assertFalse(IpHelper::isInSubnet('192.0.2.1', 'foo/24'));
		$this->assertFalse(IpHelper::isInSubnet('', '192.0.2.0/24'));
		// IPv4 vs. IPv6 never match each other
		$this->assertFalse(IpHelper::isInSubnet('192.0.2.1', '::/0'));
		$this->assertFalse(IpHelper::isInSubnet('2001:db8::1', '0.0.0.0/0'));
	}
}
