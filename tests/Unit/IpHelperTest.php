<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class IpHelperTest extends TestCase
{
	public function testIPv4Subnets()
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

	public function testIPv6Subnets()
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

	public function testParseTrustedProxies()
	{
		$this->assertSame(array('192.0.2.1'), IpHelper::parseTrustedProxies('192.0.2.1'));
		$this->assertSame(array('192.0.2.1', '198.51.100.0/24', '2001:db8::1'),
			IpHelper::parseTrustedProxies(" 192.0.2.1,198.51.100.0/24 ;\n2001:db8::1 "));
		$this->assertSame(array(), IpHelper::parseTrustedProxies(''));
	}

	public function testIsTrustedProxy()
	{
		$proxies = array('192.0.2.1', '198.51.100.0/24', '2001:db8::1');
		$this->assertTrue(IpHelper::isTrustedProxy('192.0.2.1', $proxies));
		$this->assertTrue(IpHelper::isTrustedProxy('198.51.100.77', $proxies));
		// other spelling of the same IPv6 address
		$this->assertTrue(IpHelper::isTrustedProxy('2001:0db8:0:0:0:0:0:1', $proxies));
		$this->assertFalse(IpHelper::isTrustedProxy('192.0.2.2', $proxies));
		$this->assertFalse(IpHelper::isTrustedProxy('not-an-ip', $proxies));
		$this->assertFalse(IpHelper::isTrustedProxy('', $proxies));
		$this->assertFalse(IpHelper::isTrustedProxy('192.0.2.1', array()));
		// a malformed entry never matches
		$this->assertFalse(IpHelper::isTrustedProxy('192.0.2.1', array('foo', '192.0.2.0/abc')));
	}

	public static function forwardedHeaderProvider()
	{
		$proxy = array('198.51.100.7');
		return array(
			'single entry'                      => array('HTTP_X_FORWARDED_FOR', '203.0.113.5', $proxy, '203.0.113.5'),
			// the case a proxy appending to the client's own header produces:
			// the forged entry on the left must be ignored
			'forged leftmost entry'             => array('HTTP_X_FORWARDED_FOR', '1.2.3.4, 203.0.113.5', $proxy, '203.0.113.5'),
			'several forged entries'            => array('HTTP_X_FORWARDED_FOR', '1.1.1.1, 2.2.2.2, 203.0.113.5', $proxy, '203.0.113.5'),
			'forged allowlisted address'        => array('HTTP_X_FORWARDED_FOR', '192.0.2.200, 203.0.113.5', $proxy, '203.0.113.5'),
			'trusted hops are skipped'          => array('HTTP_X_FORWARDED_FOR', '1.2.3.4, 203.0.113.5, 198.51.100.7', $proxy, '203.0.113.5'),
			'subnet of trusted proxies'         => array('HTTP_X_FORWARDED_FOR', '1.2.3.4, 203.0.113.5, 198.51.100.9', array('198.51.100.0/24'), '203.0.113.5'),
			'private client'                    => array('HTTP_X_FORWARDED_FOR', '203.0.113.5, 10.0.0.9', $proxy, '10.0.0.9'),
			'whitespace'                        => array('HTTP_X_FORWARDED_FOR', '  203.0.113.5  ', $proxy, '203.0.113.5'),
			'IPv6'                              => array('HTTP_X_FORWARDED_FOR', '1.2.3.4, 2001:db8::5', $proxy, '2001:db8::5'),
			'IPv4 with port'                    => array('HTTP_X_FORWARDED_FOR', '203.0.113.5:4711', $proxy, '203.0.113.5'),
			'bracketed IPv6 with port'          => array('HTTP_X_FORWARDED_FOR', '[2001:db8::5]:4711', $proxy, '2001:db8::5'),
			'single-value header'               => array('HTTP_CLIENT_IP', '203.0.113.5', $proxy, '203.0.113.5'),
			'Forwarded header'                  => array('HTTP_FORWARDED', 'for=1.2.3.4, for=203.0.113.5;proto=https', $proxy, '203.0.113.5'),
			'Forwarded quoted IPv6'             => array('HTTP_FORWARDED', 'for="[2001:db8::5]:4711";by=198.51.100.7', $proxy, '2001:db8::5'),
			'Forwarded case-insensitive key'    => array('HTTP_FORWARDED', 'For=203.0.113.5', $proxy, '203.0.113.5'),
			// unparseable last hop: the entries to its left are not trustworthy
			'garbage last entry'                => array('HTTP_X_FORWARDED_FOR', '203.0.113.5, not-an-ip', $proxy, null),
			'empty last entry'                  => array('HTTP_X_FORWARDED_FOR', '203.0.113.5,', $proxy, null),
			'obfuscated Forwarded identifier'   => array('HTTP_FORWARDED', 'for=203.0.113.5, for=_hidden', $proxy, null),
			'Forwarded element without for'     => array('HTTP_FORWARDED', 'for=203.0.113.5, proto=https', $proxy, null),
			'only trusted proxies'              => array('HTTP_X_FORWARDED_FOR', '198.51.100.7, 198.51.100.7', $proxy, null),
			'empty header'                      => array('HTTP_X_FORWARDED_FOR', '', $proxy, null),
		);
	}

	#[DataProvider('forwardedHeaderProvider')]
	public function testClientAddressFromHeader($header, $value, $proxies, $expected)
	{
		$this->assertSame($expected, IpHelper::clientAddressFromHeader($header, $value, $proxies));
	}
}
