<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Helper\HtaccessHelper;
use Joomla\CMS\Log\Log;

class HtaccessHelperTest extends IntegrationTestCase
{
	private string $dir;

	protected function setUp(): void
	{
		parent::setUp();
		$this->dir = sys_get_temp_dir().'/bfstop-htaccess-'.bin2hex(random_bytes(4));
		mkdir($this->dir);
	}

	protected function tearDown(): void
	{
		@chmod($this->dir.'/.htaccess', 0644);
		@unlink($this->dir.'/.htaccess');
		@rmdir($this->dir);
	}

	private function helper($logger = null)
	{
		return new HtaccessHelper($this->dir, $logger ?? $this->logger);
	}

	private function content()
	{
		return file_get_contents($this->dir.'/.htaccess');
	}

	public function testFileName()
	{
		$this->assertSame($this->dir.'/.htaccess', $this->helper()->getFileName());
	}

	public function testCheckRequirements()
	{
		$_SERVER['SERVER_SOFTWARE'] = 'Apache/2.4.58 (Ubuntu)';
		$req = $this->helper()->checkRequirements();
		$this->assertNotFalse($req['apacheserver']);
		$this->assertFalse($req['found']);

		touch($this->dir.'/.htaccess');
		$_SERVER['SERVER_SOFTWARE'] = 'nginx/1.25';
		$req = $this->helper()->checkRequirements();
		$this->assertFalse($req['apacheserver']);
		$this->assertTrue($req['found']);
		$this->assertTrue($req['readable']);
		$this->assertTrue($req['writeable']);
	}

	public function testNoFileMeansNoDeniedIPs()
	{
		$this->assertSame(array(), $this->helper()->getDeniedIPs());
	}

	public function testDenyCreatesFileWithBlock()
	{
		$h = $this->helper();
		$this->assertNotFalse($h->denyIP('203.0.113.5'));
		$this->assertSame(array('203.0.113.5'), array_values($h->getDeniedIPs()));
		$this->assertSame(
			"# BEGIN BFStop Blocks\n<RequireAll>\nRequire all granted\nRequire not ip 203.0.113.5\n</RequireAll>\n# END BFStop Blocks\n\n",
			$this->content());
	}

	public function testDenyIsIdempotentAndUndenyRemoves()
	{
		$h = $this->helper();
		$h->denyIP('203.0.113.5');
		$h->denyIP('2001:db8::/32');
		$h->denyIP('203.0.113.5');
		$this->assertSame(array('203.0.113.5', '2001:db8::/32'), array_values($h->getDeniedIPs()));

		$this->assertNotFalse($h->undenyIP('203.0.113.5'));
		$this->assertSame(array('2001:db8::/32'), array_values($h->getDeniedIPs()));

		// removing something which isn't there is not an error
		$this->assertTrue($h->undenyIP('198.51.100.1'));
	}

	public function testExistingContentIsPreserved()
	{
		$existing = "RewriteEngine On\nRewriteRule ^foo$ bar [L]\n";
		file_put_contents($this->dir.'/.htaccess', $existing);
		$h = $this->helper();
		$h->denyIP('203.0.113.5');
		$h->denyIP('203.0.113.6');
		$h->undenyIP('203.0.113.5');
		$content = $this->content();
		$this->assertStringEndsWith($existing, $content);
		$this->assertStringStartsWith("# BEGIN BFStop Blocks\n", $content);
		$this->assertSame(1, substr_count($content, '# BEGIN BFStop Blocks'));
		$this->assertSame(array('203.0.113.6'), array_values($h->getDeniedIPs()));
	}

	public function testBlockInMiddleOfFileIsUpdatedInPlace()
	{
		file_put_contents($this->dir.'/.htaccess',
			"# top\n# BEGIN BFStop Blocks\n<RequireAll>\nRequire all granted\nRequire not ip 192.0.2.1\n</RequireAll>\n# END BFStop Blocks\n# bottom\n");
		$h = $this->helper();
		$this->assertSame(array('192.0.2.1'), array_values($h->getDeniedIPs()));
		$h->denyIP('192.0.2.2');
		$content = $this->content();
		$this->assertStringStartsWith("# top\n# BEGIN BFStop Blocks\n", $content);
		$this->assertStringEndsWith("# END BFStop Blocks\n# bottom\n", $content);
		$this->assertSame(array('192.0.2.1', '192.0.2.2'), array_values($h->getDeniedIPs()));
	}

	public function test403Message()
	{
		$h = $this->helper();
		$h->denyIP('203.0.113.5');
		$this->assertNotFalse($h->edit403Message('Go away'));
		$this->assertStringContainsString("ErrorDocument 403 \"Go away\"\n", $this->content());
		$this->assertSame(array('203.0.113.5'), array_values($h->getDeniedIPs()));

		$h->edit403Message('Changed');
		$this->assertStringNotContainsString('Go away', $this->content());
		$this->assertSame(1, substr_count($this->content(), 'ErrorDocument 403'));

		$h->edit403Message('');
		$this->assertStringNotContainsString('ErrorDocument 403', $this->content());
		$this->assertSame(array('203.0.113.5'), array_values($h->getDeniedIPs()));
	}

	public function testCorruptMarkersAreNotOverwritten()
	{
		$corrupt = "# BEGIN BFStop Blocks\nRequire not ip 192.0.2.1\n";
		file_put_contents($this->dir.'/.htaccess', $corrupt);
		$logger = $this->logger;
		$this->assertFalse($this->helper($logger)->denyIP('203.0.113.5'));
		$this->assertSame($corrupt, $this->content());
		$this->assertTrue($logger->hasMessage(Log::ERROR, 'END'));
		$logger->errors = array(); // expected
	}

	public function testReadOnlyFileIsReported()
	{
		if (function_exists('posix_geteuid') && posix_geteuid() === 0)
		{
			$this->markTestSkipped('root can write read-only files');
		}
		file_put_contents($this->dir.'/.htaccess', "# existing\n");
		chmod($this->dir.'/.htaccess', 0444);
		$logger = $this->logger;
		$this->assertFalse($this->helper($logger)->denyIP('203.0.113.5'));
		$this->assertTrue($logger->hasMessage(Log::ERROR, 'not writable'));
		$logger->errors = array(); // expected
	}
}
