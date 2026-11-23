<?php
/*
 * @package BFStop for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Library\Bfstop\Service\Setup\ProxyDetector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * How the setup assistant tells from the administrator's request how the
 * site is reached (see the plan, docs/setup-assistant-plan.md, 5.1). The
 * plugin's installer script makes the same distinction without the library;
 * InstallerScriptTest checks it with these scenarios too.
 */
class ProxyDetectorTest extends TestCase
{
	private const NoProxy = array('useProxy' => false, 'header' => 'HTTP_X_FORWARDED_FOR', 'trusted' => array());

	/** name => array($_SERVER, scenario) */
	public static function scenarios(): array
	{
		return array(
			'A: direct, public' => array(array('REMOTE_ADDR' => '203.0.113.5'), 'A'),
			'A: direct, from the local network, no header' => array(array('REMOTE_ADDR' => '192.168.1.20'), 'A'),
			'A: an empty header is none' => array(array('REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => ' '), 'A'),
			'B: load balancer of the private network' => array(array('REMOTE_ADDR' => '10.0.0.5',
				'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), 'B'),
			'B: reverse proxy on the same host' => array(array('REMOTE_ADDR' => '127.0.0.1',
				'HTTP_FORWARDED' => 'for=203.0.113.7;proto=https'), 'B'),
			'B: IPv6 unique local' => array(array('REMOTE_ADDR' => 'fd00::5', 'HTTP_X_FORWARDED_FOR' => '2001:db8::7'), 'B'),
			'B: carrier-grade NAT range' => array(array('REMOTE_ADDR' => '100.64.0.9', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), 'B'),
			'B: IPv4-mapped private address' => array(array('REMOTE_ADDR' => '::ffff:10.0.0.5',
				'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), 'B'),
			'C: the web server resolves the address' => array(array('REMOTE_ADDR' => '203.0.113.7',
				'HTTP_X_FORWARDED_FOR' => '198.51.100.1, 203.0.113.7'), 'C'),
			'C: with Forwarded and a port' => array(array('REMOTE_ADDR' => '2001:db8::7',
				'HTTP_FORWARDED' => 'for="[2001:db8::7]:4711"'), 'C'),
			'C: mod_remoteip with CF-Connecting-IP' => array(array('REMOTE_ADDR' => '203.0.113.7',
				'HTTP_CF_CONNECTING_IP' => '203.0.113.7'), 'C'),
			'D: CDN with public edge addresses' => array(array('REMOTE_ADDR' => '198.51.100.20',
				'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), 'D'),
			'D: CF-Connecting-IP only' => array(array('REMOTE_ADDR' => '198.51.100.20',
				'HTTP_CF_CONNECTING_IP' => '203.0.113.7'), 'D'),
			'D: corporate proxy on the administrator\'s side' => array(array('REMOTE_ADDR' => '198.51.100.30',
				'HTTP_X_FORWARDED_FOR' => '10.20.30.40'), 'D'),
			'D: a header whose last entry is no address' => array(array('REMOTE_ADDR' => '198.51.100.20',
				'HTTP_X_FORWARDED_FOR' => '203.0.113.7, unknown'), 'D'),
			'E: X-Real-IP only' => array(array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.7'), 'E'),
			'E: unsupported headers only, from a public address' => array(array('REMOTE_ADDR' => '198.51.100.20',
				'HTTP_TRUE_CLIENT_IP' => '203.0.113.7', 'HTTP_FASTLY_CLIENT_IP' => '203.0.113.7'), 'E'),
			'B, not E: an unsupported header besides a supported one' => array(array('REMOTE_ADDR' => '10.0.0.5',
				'HTTP_X_REAL_IP' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), 'B'),
		);
	}

	#[DataProvider('scenarios')]
	public function testScenario(array $server, string $expected)
	{
		$this->assertSame($expected, ProxyDetector::detect($server, self::NoProxy, false)['scenario']);
	}

	public function testWhatIsDetected()
	{
		$detected = ProxyDetector::detect(array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7',
			'HTTP_FORWARDED' => 'for=203.0.113.7', 'HTTP_X_REAL_IP' => '203.0.113.7'), self::NoProxy, true);
		$this->assertTrue($detected['remoteNonPublic']);
		$this->assertSame('HTTP_FORWARDED', $detected['header'], 'Forwarded is preferred');
		$this->assertSame('203.0.113.7', $detected['last']);
		$this->assertSame(array('HTTP_X_REAL_IP' => 'X-Real-IP'), $detected['unsupported']);
		$this->assertSame(array('HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED'), array_keys($detected['supported']));
		$this->assertFalse($detected['cloudflare']);
		$this->assertTrue($detected['behindLoadBalancer']);
		$this->assertFalse($detected['fromTrusted']);
		$trusted = array('useProxy' => true, 'header' => 'HTTP_FORWARDED', 'trusted' => array('10.0.0.0/24'));
		$this->assertTrue(ProxyDetector::detect(array('REMOTE_ADDR' => '10.0.0.5'), $trusted, false)['fromTrusted']);
		$this->assertFalse(ProxyDetector::detect(array('REMOTE_ADDR' => '10.0.0.5'),
			array('useProxy' => false) + $trusted, false)['fromTrusted'], 'no proxy trusted while proxy support is off');
	}

	public function testProposal()
	{
		$this->assertSame(array('useProxy' => 1, 'proxyHeaderSource' => 'HTTP_X_FORWARDED_FOR', 'proxyIpAddress' => '10.0.0.5'),
			ProxyDetector::proposal(ProxyDetector::detect(array('REMOTE_ADDR' => '::ffff:10.0.0.5',
				'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), self::NoProxy, false)), 'B: trust the exact address');
		$this->assertSame(array('useProxy' => 1, 'proxyHeaderSource' => 'HTTP_CF_CONNECTING_IP', 'proxyIpAddress' => ''),
			ProxyDetector::proposal(ProxyDetector::detect(array('REMOTE_ADDR' => '198.51.100.20',
			'HTTP_CF_CONNECTING_IP' => '203.0.113.7'), self::NoProxy, false)), 'D: Cloudflare, whose ranges are fetched');
		$this->assertSame(array('useProxy' => 1, 'proxyHeaderSource' => 'HTTP_X_FORWARDED_FOR', 'proxyIpAddress' => ''),
			ProxyDetector::proposal(ProxyDetector::detect(array('REMOTE_ADDR' => '198.51.100.20',
			'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), self::NoProxy, false)), 'D: not the one server of the CDN the request came from');
		foreach (array('A' => array('REMOTE_ADDR' => '203.0.113.5'),
			'C' => array('REMOTE_ADDR' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'),
			'E' => array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.7')) as $scenario => $server)
		{
			$this->assertSame(array('useProxy' => 0), ProxyDetector::proposal(ProxyDetector::detect($server, self::NoProxy, false)), $scenario);
		}
	}

	/** The dry run: the address BFStop would take with settings not saved yet. */
	public function testPreview()
	{
		$server = array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1, 203.0.113.7');
		$this->assertSame(array('address' => '203.0.113.7', 'problem' => null),
			ProxyDetector::preview($server, true, 'HTTP_X_FORWARDED_FOR', '10.0.0.5'));
		$this->assertSame(array('address' => '10.0.0.5', 'problem' => null), ProxyDetector::preview($server, false, '', ''));
		$this->assertSame('notTrusted', ProxyDetector::preview($server, true, 'HTTP_X_FORWARDED_FOR', '10.0.0.6')['problem']);
		$this->assertSame('notTrusted', ProxyDetector::preview($server, true, 'HTTP_X_FORWARDED_FOR', '')['problem']);
		$this->assertSame('noHeader', ProxyDetector::preview($server, true, 'HTTP_FORWARDED', '10.0.0.5')['problem']);
		$this->assertSame('unusable', ProxyDetector::preview($server, true, 'HTTP_X_FORWARDED_FOR',
			'10.0.0.5, 203.0.113.0/24, 198.51.100.0/24')['problem'], 'every entry is a trusted proxy');
		// a corporate proxy on the administrator's side shows up as the address of its network
		$this->assertSame('10.20.30.40', ProxyDetector::preview(array('REMOTE_ADDR' => '198.51.100.30',
			'HTTP_X_FORWARDED_FOR' => '10.20.30.40'), true, 'HTTP_X_FORWARDED_FOR', '198.51.100.30')['address']);
	}

	public function testFingerprint()
	{
		$fingerprint = ProxyDetector::fingerprint('B', 'HTTP_X_FORWARDED_FOR', true);
		$this->assertMatchesRegularExpression('/^[0-9a-f]{12}$/', $fingerprint);
		$this->assertSame($fingerprint, ProxyDetector::fingerprint('B', 'HTTP_X_FORWARDED_FOR', true));
		$this->assertNotSame($fingerprint, ProxyDetector::fingerprint('B', 'HTTP_FORWARDED', true));
		$this->assertNotSame($fingerprint, ProxyDetector::fingerprint('B', 'HTTP_X_FORWARDED_FOR', false));
		$this->assertNotSame($fingerprint, ProxyDetector::fingerprint('D', 'HTTP_X_FORWARDED_FOR', true));
	}

	/** Joomla's "Behind Load Balancer": information only (plan, 5.6). */
	public function testLoadBalancerHint()
	{
		$this->assertSame('switchOn', ProxyDetector::loadBalancerHint(true, 'B', false));
		$this->assertNull(ProxyDetector::loadBalancerHint(true, 'B', true));
		$this->assertSame('switchOff', ProxyDetector::loadBalancerHint(false, 'A', true));
		$this->assertSame('switchOff', ProxyDetector::loadBalancerHint(false, 'C', true));
		$this->assertNull(ProxyDetector::loadBalancerHint(false, 'B', true), 'the proxy step comes first');
		$this->assertNull(ProxyDetector::loadBalancerHint(false, 'A', false));
	}

	public function testWhichScenariosNeedProxySettings()
	{
		$this->assertSame(array('B', 'D', 'E'), array_values(array_filter(array('A', 'B', 'C', 'D', 'E'),
			array(ProxyDetector::class, 'needsProxySettings'))));
	}
}
