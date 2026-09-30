<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Component\Bfstop\Administrator\Helper\IpRangeHelper;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * IP range helper of the component (https://github.com/codeling/com_bfstop),
 * loaded from the checkout given in COM_BFSTOP_ROOT.
 */
class IpRangeHelperTest extends TestCase
{
	protected function setUp(): void
	{
		if (!class_exists(IpRangeHelper::class))
		{
			$this->markTestSkipped('COM_BFSTOP_ROOT not set, see tests/README.md');
		}
	}

	public function testIsIPv6()
	{
		$this->assertTrue(IpRangeHelper::isIPv6('2001:db8::1'));
		$this->assertTrue(IpRangeHelper::isIPv6('::1'));
		$this->assertFalse(IpRangeHelper::isIPv6('192.0.2.1'));
	}

	public static function rangeProvider()
	{
		return array(
			'v4 /32'             => array('192.0.2.7/32', '192.0.2.7', '192.0.2.7'),
			'v4 /24'             => array('192.0.2.0/24', '192.0.2.0', '192.0.2.255'),
			'v4 /24 misaligned'  => array('192.0.2.77/24', '192.0.2.0', '192.0.2.255'),
			'v4 /20'             => array('10.1.17.3/20', '10.1.16.0', '10.1.31.255'),
			'v4 /1'              => array('200.0.0.1/1', '128.0.0.0', '255.255.255.255'),
			'v4 /0'              => array('192.0.2.1/0', '0.0.0.0', '255.255.255.255'),
			'v6 /128'            => array('2001:db8::1/128', '2001:db8::1', '2001:db8::1'),
			'v6 /64'             => array('2001:db8:0:1::/64', '2001:db8:0:1::', '2001:db8:0:1:ffff:ffff:ffff:ffff'),
			'v6 /64 misaligned'  => array('2001:db8:0:1:2:3:4:5/64', '2001:db8:0:1::', '2001:db8:0:1:ffff:ffff:ffff:ffff'),
			'v6 /33 odd bits'    => array('2001:db8:ffff::/33', '2001:db8:8000::', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'),
			'v6 /0'              => array('2001:db8::/0', '::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
		);
	}

	#[DataProvider('rangeProvider')]
	public function testCidrToRange($cidr, $start, $end)
	{
		$this->assertSame(array($start, $end), IpRangeHelper::cidrToRange($cidr));
	}

	public function testNumOfAddresses()
	{
		$this->assertEquals(1, IpRangeHelper::numOfAddresses('192.0.2.1/32'));
		$this->assertEquals(256, IpRangeHelper::numOfAddresses('192.0.2.0/24'));
		$this->assertEquals(4294967296, IpRangeHelper::numOfAddresses('0.0.0.0/0'));
		$this->assertEquals(1, IpRangeHelper::numOfAddresses('2001:db8::1/128'));
		$this->assertEquals(pow(2, 64), IpRangeHelper::numOfAddresses('2001:db8::/64'));
	}

	public function testFormatCount()
	{
		$this->assertSame('256', IpRangeHelper::formatCount(256));
		$this->assertSame('18446744073709551616', IpRangeHelper::formatCount(IpRangeHelper::numOfAddresses('2001:db8::/64')));
		$this->assertStringNotContainsString('E', IpRangeHelper::formatCount(IpRangeHelper::numOfAddresses('::/0')));
	}

	public static function maskProvider()
	{
		return array(
			array(0,   str_repeat("\x00", 16)),
			array(1,   "\x80".str_repeat("\x00", 15)),
			array(7,   "\xfe".str_repeat("\x00", 15)),
			array(8,   "\xff".str_repeat("\x00", 15)),
			array(9,   "\xff\x80".str_repeat("\x00", 14)),
			array(127, str_repeat("\xff", 15)."\xfe"),
			array(128, str_repeat("\xff", 16)),
		);
	}

	#[DataProvider('maskProvider')]
	public function testIpv6Mask($bits, $expected)
	{
		$mask = IpRangeHelper::ipv6Mask($bits);
		$this->assertSame(16, strlen($mask));
		$this->assertSame(bin2hex($expected), bin2hex($mask));
	}
}
