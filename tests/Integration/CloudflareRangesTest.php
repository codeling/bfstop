<?php
/*
 * @package BFStop for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Component\Bfstop\Administrator\Model\SetupModel;

/**
 * The setup assistant fetches Cloudflare's ranges (SetupModel::cloudflareRanges())
 * with Joomla's HTTP client: from a local web server here, which serves them
 * as cloudflare.com does - and redirects and long answers, which are refused.
 */
class CloudflareRangesTest extends IntegrationTestCase
{
	private $server = null;
	private $port = 0;

	protected function setUp(): void
	{
		parent::setUp();
		$listener = stream_socket_server('tcp://127.0.0.1:0');
		$this->port = (int) substr(strrchr(stream_socket_get_name($listener, false), ':'), 1);
		fclose($listener);
		$this->server = proc_open('exec '.escapeshellarg(PHP_BINARY).' -S 127.0.0.1:'.$this->port.' '.
			escapeshellarg(__DIR__.'/fixtures/cloudflare.php'), array(0 => array('file', '/dev/null', 'r'),
			1 => array('file', '/dev/null', 'w'), 2 => array('file', '/dev/null', 'w')), $pipes);
		for ($i = 0; $i < 50; ++$i)
		{
			if (($socket = @fsockopen('127.0.0.1', $this->port)) !== false)
			{
				fclose($socket);
				return;
			}
			usleep(100000);
		}
		$this->markTestSkipped('could not start the PHP web server');
	}

	protected function tearDown(): void
	{
		if ($this->server)
		{
			proc_terminate($this->server);
			proc_close($this->server);
		}
	}

	private function url($path)
	{
		return 'http://127.0.0.1:'.$this->port.$path;
	}

	public function testTheRangesAreFetched()
	{
		$this->assertSame(array('173.245.48.0/20', '103.21.244.0/22', '2400:cb00::/32', '2606:4700::/32'),
			SetupModel::cloudflareRanges(array($this->url('/ips-v4'), $this->url('/ips-v6'))));
	}

	public function testARedirectIsNotFollowed()
	{
		$this->assertNull(SetupModel::cloudflareRanges(array($this->url('/redirect'))));
		$this->assertFalse(SetupModel::cloudflareHttpOptions()['follow_location']);
	}

	public function testALongAnswerIsRefused()
	{
		$this->assertNull(SetupModel::cloudflareRanges(array($this->url('/big'))));
	}

	public function testWhatIsNoRangeOfAProxyIsRefused()
	{
		$this->assertNull(SetupModel::cloudflareRanges(array($this->url('/wide'))));
		$this->assertNull(SetupModel::cloudflareRanges(array($this->url('/ips-v4'), $this->url('/missing'))));
	}
}
