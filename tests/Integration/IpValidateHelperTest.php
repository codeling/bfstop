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
 * IP address validation of the component (component/).
 */
class IpValidateHelperTest extends IntegrationTestCase
{
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

	public function testARangeHoldingTheCurrentAddressIsAnError()
	{
		$remoteAddr = $_SERVER['REMOTE_ADDR'] ?? null;
		try
		{
			$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::5';
			$error = IpValidateHelper::currentIpError('2001:db8:1::/48');
			$this->assertNotNull($error);
			$this->assertStringContainsString('2001:db8:1:2::5', $error);
			$this->assertNotNull(IpValidateHelper::currentIpError('2001:DB8:1:2:0::5'), 'the same address, spelt differently');
			$this->assertNull(IpValidateHelper::currentIpError('2001:db8:2::/48'));
			$this->assertNull(IpValidateHelper::currentIpError('203.0.113.0/24'), 'the other family');
			$this->assertSame(array(), $this->messages(), 'nothing is posted: the rule returns the error');
		}
		finally
		{
			if ($remoteAddr === null)
			{
				unset($_SERVER['REMOTE_ADDR']);
			}
			else
			{
				$_SERVER['REMOTE_ADDR'] = $remoteAddr;
			}
		}
	}

	public static function validRangeProvider()
	{
		return array(
			array('203.0.113.5'),
			array('203.0.113.0/24'),
			array('44.0.0.0/8'),
			array('2001::/16'),
			array('203.0.113.0/32'),
			array('2001:4860:4860::8888'),
			array('2001:4860::/32'),
			array('2001:4860::/128'),
		);
	}

	#[DataProvider('validRangeProvider')]
	public function testValidPublicRange($range)
	{
		$this->assertNull(IpValidateHelper::rangeError($range));
		$this->assertNull(IpValidateHelper::privateRangeNote($range));
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

	public static function tooLargeNetworkProvider()
	{
		// a whole address family, or a large share of it
		return array(array('203.0.113.0/0'), array('0.0.0.0/0'), array('128.0.0.0/1'), array('44.0.0.0/7'),
			array('::/0'), array('2000::/3'), array('2001::/15'));
	}

	#[DataProvider('tooLargeNetworkProvider')]
	public function testTooLargeNetworkIsRefused($range)
	{
		$this->assertSame(Text::sprintf('COM_BFSTOP_IP_NETWORK_TOO_LARGE', $range,
			IpValidateHelper::MinPrefixIPv4, IpValidateHelper::MinPrefixIPv6), IpValidateHelper::rangeError($range));
	}

	#[DataProvider('invalidRangeProvider')]
	public function testInvalidRange($range, $expectedKey, $expectedArg)
	{
		$this->assertSame(Text::sprintf($expectedKey, $expectedArg), IpValidateHelper::rangeError($range));
		$this->assertSame(array(), $this->messages());
	}

	public static function privateRangeProvider()
	{
		return array(array('10.0.0.1'), array('192.168.0.0/16'), array('127.0.0.1'), array('fd00::1'), array('::1'));
	}

	#[DataProvider('privateRangeProvider')]
	public function testPrivateOrReservedRangeIsAcceptedWithANote($range)
	{
		$this->assertNull(IpValidateHelper::rangeError($range));
		$ip = explode('/', $range)[0];
		$this->assertSame(Text::sprintf('COM_BFSTOP_IP_PRIVATE_OR_RESERVED', $ip), IpValidateHelper::privateRangeNote($range));
	}

	public function testTheRulesReturnTheErrorAndPostOnlyTheNote()
	{
		// Joomla shows the error a rule returns instead of its own "invalid
		// field"; the rules used to post theirs on top of it
		$element = new \SimpleXMLElement('<field name="ipaddress"/>');
		$rule = new \Codeling\Component\Bfstop\Administrator\Rule\IprangeRule();
		$result = $rule->test($element, '203.0.113.0/33');
		$this->assertInstanceOf(\UnexpectedValueException::class, $result);
		$this->assertSame(Text::sprintf('COM_BFSTOP_IP_INVALID_SUBNET', '33'), $result->getMessage());
		$this->assertSame(array(), $this->messages());
		$this->assertTrue($rule->test($element, '10.0.0.1'));
		$this->assertCount(1, $this->messages(), 'a private range is noted');
		$remoteAddr = $_SERVER['REMOTE_ADDR'] ?? null;
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
		try
		{
			$block = new \Codeling\Component\Bfstop\Administrator\Rule\IprangeblockRule();
			$this->assertInstanceOf(\UnexpectedValueException::class, $block->test($element, '203.0.113.0/24'));
			$this->assertTrue($block->test($element, '198.51.100.0/24'));
		}
		finally
		{
			$_SERVER['REMOTE_ADDR'] = $remoteAddr;
		}
	}
}
