<?php
/*
 * @package BFStop for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Library\Bfstop\Service\Setup\ProxyMismatch;
use Codeling\Library\Bfstop\Service\Setup\SetupState;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The mismatch check of the administrator's own request and the saved proxy
 * settings: every row of the table in section 6 of the plan
 * (docs/setup-assistant-plan.md), and dismissing by fingerprint.
 */
class ProxyMismatchTest extends TestCase
{
	private const NoProxy = array('useProxy' => false, 'header' => 'HTTP_X_FORWARDED_FOR', 'trusted' => array());
	private const Proxy = array('useProxy' => true, 'header' => 'HTTP_X_FORWARDED_FOR', 'trusted' => array('10.0.0.5'));

	/** name => array(proxy settings, $_SERVER, behind load balancer, the codes of the mismatches) */
	public static function rows(): array
	{
		return array(
			'no proxy: none there' => array(self::NoProxy, array('REMOTE_ADDR' => '203.0.113.5'), false, array()),
			'no proxy: a forwarding header from a private address' => array(self::NoProxy,
				array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), false, array('appearsBehindProxy')),
			'no proxy: CF-Connecting-IP' => array(self::NoProxy,
				array('REMOTE_ADDR' => '198.51.100.20', 'HTTP_CF_CONNECTING_IP' => '203.0.113.7'), false, array('appearsBehindProxy')),
			'no proxy: a header from a public address (a corporate proxy, or C)' => array(self::NoProxy,
				array('REMOTE_ADDR' => '198.51.100.30', 'HTTP_X_FORWARDED_FOR' => '10.20.30.40'), false, array()),
			'proxy: from the trusted proxy, with its header' => array(self::Proxy,
				array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), true, array()),
			'proxy: a header, but not from a trusted proxy' => array(self::Proxy,
				array('REMOTE_ADDR' => '10.0.0.6', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), true, array('proxyAddressChanged')),
			'proxy: no header, not from a trusted proxy' => array(self::Proxy,
				array('REMOTE_ADDR' => '203.0.113.7'), true, array('proxyRemoved')),
			'proxy: from the trusted proxy, another header' => array(self::Proxy,
				array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_FORWARDED' => 'for=203.0.113.7'), true, array('headerChanged')),
			'proxy: from the trusted proxy, no header at all' => array(self::Proxy,
				array('REMOTE_ADDR' => '10.0.0.5'), true, array()),
			'proxy: the public address the header ends in' => array(self::Proxy,
				array('REMOTE_ADDR' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1, 203.0.113.7'), true, array('serverResolves')),
			'any: only unsupported headers' => array(self::NoProxy,
				array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.7'), false, array('unsupportedHeader')),
			'any: only unsupported headers, with a proxy' => array(self::Proxy,
				array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.7'), true, array('unsupportedHeader')),
			'proxy, "Behind Load Balancer" off' => array(self::Proxy,
				array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), false, array('loadBalancer')),
			'no proxy, "Behind Load Balancer" on' => array(self::NoProxy, array('REMOTE_ADDR' => '203.0.113.5'), true, array('loadBalancer')),
		);
	}

	#[DataProvider('rows')]
	public function testRow(array $proxy, array $server, bool $behindLoadBalancer, array $expected)
	{
		$mismatches = ProxyMismatch::check($server, $proxy, $behindLoadBalancer);
		$this->assertSame($expected, array_column($mismatches, 'code'));
		foreach ($mismatches as $mismatch)
		{
			$this->assertMatchesRegularExpression('/^[0-9a-f]{12}$/', $mismatch['fingerprint']);
			$this->assertFalse($mismatch['dismissed']);
			$this->assertSame($mismatch['code'] === ProxyMismatch::LoadBalancer, $mismatch['information']);
		}
	}

	public function testTheLoadBalancerHintIsInformationOnly()
	{
		$mismatches = ProxyMismatch::check(array('REMOTE_ADDR' => '203.0.113.5'), self::NoProxy, true);
		$this->assertSame('switchOff', $mismatches[0]['hint']);
		$this->assertCount(1, ProxyMismatch::open($mismatches));
		$this->assertCount(0, ProxyMismatch::open($mismatches, true), 'no warning');
	}

	/**
	 * "This is expected" dismisses that mismatch everywhere; a different one
	 * shows again. The fingerprint holds no address: the same mismatch from
	 * another address of the same kind stays dismissed.
	 */
	public function testDismissingByFingerprint()
	{
		$vpn = array('REMOTE_ADDR' => '10.8.0.5');
		$mismatch = ProxyMismatch::check($vpn, self::Proxy, true)[0];
		$this->assertSame('proxyRemoved', $mismatch['code']);
		$state = SetupState::fromRows(array());
		$state->dismiss($mismatch['fingerprint']);
		$this->assertTrue(ProxyMismatch::check($vpn, self::Proxy, true, $state)[0]['dismissed']);
		$this->assertSame(array(), ProxyMismatch::open(ProxyMismatch::check($vpn, self::Proxy, true, $state)));
		$this->assertTrue(ProxyMismatch::check(array('REMOTE_ADDR' => '10.8.0.77'), self::Proxy, true, $state)[0]['dismissed'],
			'another address of the same network kind');
		$this->assertStringNotContainsString('10.8.0.5', implode(',', $state->toRows()));

		// a different mismatch shows again
		$other = ProxyMismatch::check(array('REMOTE_ADDR' => '10.0.0.6', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), self::Proxy, true, $state);
		$this->assertSame('proxyAddressChanged', $other[0]['code']);
		$this->assertFalse($other[0]['dismissed']);
		// the same code with other headers is another mismatch too
		$public = ProxyMismatch::check(array('REMOTE_ADDR' => '203.0.113.9'), self::Proxy, true, $state);
		$this->assertFalse($public[0]['dismissed'], 'from a public address');

		// stored and read back
		$reloaded = SetupState::fromRows($state->toRows());
		$this->assertTrue($reloaded->isDismissed($mismatch['fingerprint']));
	}
}
