<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Component\Bfstop\Administrator\Helper\IpValidateHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * IP address validation of the component (https://github.com/codeling/com_bfstop),
 * loaded from the checkout given in COM_BFSTOP_ROOT.
 */
class IpValidateHelperTest extends IntegrationTestCase
{
	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		if (!getenv('COM_BFSTOP_ROOT'))
		{
			self::markTestSkipped('COM_BFSTOP_ROOT not set, see tests/README.md');
		}
	}

	protected function setUp(): void
	{
		parent::setUp();
		$this->messages(); // start with an empty message queue
	}

	/** returns and clears the application's message queue */
	private function messages()
	{
		return Factory::getApplication()->getMessageQueue(true);
	}

	public static function cidrMatchProvider()
	{
		return array(
			'v4 exact, no prefix'        => array('192.0.2.1', '192.0.2.1', true),
			'v4 exact, no prefix, other' => array('192.0.2.2', '192.0.2.1', false),
			'v4 /32'                     => array('192.0.2.1', '192.0.2.1/32', true),
			'v4 /24 inside'              => array('192.0.2.200', '192.0.2.0/24', true),
			'v4 /24 outside'             => array('192.0.3.1', '192.0.2.0/24', false),
			'v4 /24 misaligned subnet'   => array('192.0.2.200', '192.0.2.99/24', true),
			'v4 /0 matches everything'   => array('203.0.113.9', '0.0.0.0/0', true),
			'v6 exact, no prefix'        => array('2001:db8::1', '2001:db8::1', true),
			'v6 exact, other'            => array('2001:db8::2', '2001:db8::1', false),
			'v6 /64 inside'              => array('2001:db8:0:1:abcd::1', '2001:db8:0:1::/64', true),
			'v6 /64 outside'             => array('2001:db8:0:2::1', '2001:db8:0:1::/64', false),
			'v6 /64 misaligned subnet'   => array('2001:db8:0:1::5', '2001:db8:0:1:ffff::/64', true),
			'v6 /33 odd bits inside'     => array('2001:db8:8000::1', '2001:db8:ffff::/33', true),
			'v6 /33 odd bits outside'    => array('2001:db8:7fff::1', '2001:db8:ffff::/33', false),
			'v4 address vs v6 range'     => array('192.0.2.1', '2001:db8::/32', false),
			'invalid address vs v6'      => array('garbage', '2001:db8::/32', false),
		);
	}

	#[DataProvider('cidrMatchProvider')]
	public function testCidrMatch($ip, $range, $expected)
	{
		$this->assertSame($expected, IpValidateHelper::cidrMatch($ip, $range));
	}

	public static function validRangeProvider()
	{
		return array(
			array('203.0.113.5'),
			array('203.0.113.0/24'),
			array('203.0.113.0/0'),
			array('203.0.113.0/32'),
			array('2001:4860:4860::8888'),
			array('2001:4860::/32'),
			array('2001:4860::/128'),
		);
	}

	#[DataProvider('validRangeProvider')]
	public function testValidPublicRange($range)
	{
		$this->assertTrue(IpValidateHelper::validIPRange($range));
		$this->assertSame(array(), $this->messages());
	}

	public static function invalidRangeProvider()
	{
		return array(
			'v4 subnet too large'   => array('203.0.113.0/33', 'COM_BFSTOP_IP_INVALID_SUBNET', '33'),
			'v6 subnet too large'   => array('2001:4860::/129', 'COM_BFSTOP_IP_INVALID_SUBNET', '129'),
			'negative subnet'       => array('203.0.113.0/-1', 'COM_BFSTOP_IP_INVALID_SUBNET', '-1'),
			'non-numeric subnet'    => array('203.0.113.0/abc', 'COM_BFSTOP_IP_INVALID_SUBNET', 'abc'),
			'empty subnet'          => array('203.0.113.0/', 'COM_BFSTOP_IP_INVALID_SUBNET', ''),
			// is_numeric() accepts these; they must not get as far as a config file
			'exponent subnet'       => array('203.0.113.0/1e1', 'COM_BFSTOP_IP_INVALID_SUBNET', '1e1'),
			'hex subnet'            => array('203.0.113.0/0x8', 'COM_BFSTOP_IP_INVALID_SUBNET', '0x8'),
			'fractional subnet'     => array('203.0.113.0/8.5', 'COM_BFSTOP_IP_INVALID_SUBNET', '8.5'),
			'padded subnet'         => array('203.0.113.0/ 8', 'COM_BFSTOP_IP_INVALID_SUBNET', ' 8'),
			'subnet with newline'   => array("203.0.113.0/8\n", 'COM_BFSTOP_IP_INVALID_SUBNET', "8\n"),
			'not an address'        => array('foo.bar', 'COM_BFSTOP_IP_INVALID_ADDRESS', 'foo.bar'),
			'octet out of range'    => array('203.0.113.256', 'COM_BFSTOP_IP_INVALID_ADDRESS', '203.0.113.256'),
			'empty'                 => array('', 'COM_BFSTOP_IP_INVALID_ADDRESS', ''),
			'invalid with subnet'   => array('1.2.3/24', 'COM_BFSTOP_IP_INVALID_ADDRESS', '1.2.3'),
		);
	}

	#[DataProvider('invalidRangeProvider')]
	public function testInvalidRange($range, $expectedKey, $expectedArg)
	{
		$this->assertFalse(IpValidateHelper::validIPRange($range));
		$this->assertSame(array(array('message' => Text::sprintf($expectedKey, $expectedArg), 'type' => 'warning')), $this->messages());
	}

	public static function privateRangeProvider()
	{
		return array(array('10.0.0.1'), array('192.168.0.0/16'), array('127.0.0.1'), array('fd00::1'), array('::1'));
	}

	#[DataProvider('privateRangeProvider')]
	public function testPrivateOrReservedRangeIsAcceptedWithWarning($range)
	{
		$this->assertTrue(IpValidateHelper::validIPRange($range));
		$ip = explode('/', $range)[0];
		$this->assertSame(array(array('message' => Text::sprintf('COM_BFSTOP_IP_PRIVATE_OR_RESERVED', $ip), 'type' => 'warning')), $this->messages());
	}
}
