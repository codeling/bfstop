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
use PHPUnit\Framework\Attributes\DataProvider;

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
			"# BEGIN BFStop Blocks\n<If \"-R '203.0.113.5'\">\nRequire all denied\n</If>\n# END BFStop Blocks\n\n",
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

	public static function invalidAddressProvider()
	{
		return array(
			'injected directive' => array("192.0.2.1\nSetHandler application/x-httpd-php"),
			'exponent prefix'    => array('192.0.2.0/1e1'),
			'prefix too long'    => array('192.0.2.0/33'),
			'trailing newline'   => array("192.0.2.1\n"),
			'host name'          => array('example.org'),
			'empty'              => array(''),
		);
	}

	#[DataProvider('invalidAddressProvider')]
	public function testDenyRefusesAnythingButAnAddress($address)
	{
		$h = $this->helper();
		$h->denyIP('192.0.2.7');
		$before = $this->content();
		$this->assertFalse($h->denyIP($address));
		$this->assertSame($before, $this->content(), 'file must stay untouched');
		$this->assertTrue($this->logger->hasMessage(Log::ERROR, 'Refusing to write'));
		$this->logger->errors = array(); // expected
	}

	public function test403MessageIsSanitised()
	{
		$h = $this->helper();
		$this->assertFalse($h->edit403Message("Go away\nSetHandler application/x-httpd-php"));
		$this->assertFalse($h->edit403Message("Go away\r"));
		$this->assertFileDoesNotExist($this->dir.'/.htaccess');
		$this->logger->errors = array(); // expected
		$this->assertNotFalse($h->edit403Message('Say "hi" \\ bye'));
		$this->assertStringContainsString('ErrorDocument 403 "Say \"hi\" \\\\ bye"'."\n", $this->content());
	}

	public function testConcurrentChangesDontLoseEntries()
	{
		// each request which blocks an IP address reads the file, adds a line
		// and writes it back; without a lock around that cycle, parallel
		// requests overwrite each other's lines
		$count = 24;
		$processes = array();
		for ($i = 1; $i <= $count; ++$i)
		{
			$command = escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/fixtures/deny_ip.php').' '.
				escapeshellarg($this->dir).' '.escapeshellarg('198.51.100.'.$i);
			$processes[$i] = proc_open($command, array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes[$i]);
		}
		foreach ($processes as $i => $process)
		{
			stream_get_contents($pipes[$i][1]);
			stream_get_contents($pipes[$i][2]);
			proc_close($process);
		}
		$denied = $this->helper()->getDeniedIPs();
		sort($denied);
		$expected = array();
		for ($i = 1; $i <= $count; ++$i)
		{
			$expected[] = '198.51.100.'.$i;
		}
		sort($expected);
		$this->assertSame($expected, $denied);
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

	public function testWritingReplacesTheFileWithoutLeavingTemporaryFiles()
	{
		file_put_contents($this->dir.'/.htaccess', "RewriteEngine On\n");
		chmod($this->dir.'/.htaccess', 0640);
		$this->assertTrue($this->helper()->denyIP('203.0.113.5'));
		$this->assertStringContainsString("-R '203.0.113.5'", $this->content());
		$this->assertStringContainsString('RewriteEngine On', $this->content());
		$this->assertSame(0640, fileperms($this->dir.'/.htaccess') & 0777, 'the permissions are kept');
		$this->assertSame(array('.htaccess'), array_values(array_diff(scandir($this->dir), array('.', '..'))));
	}

	public function testWritingKeepsASymbolicLink()
	{
		$real = $this->dir.'/real-htaccess';
		file_put_contents($real, "RewriteEngine On\n");
		symlink($real, $this->dir.'/.htaccess');
		try
		{
			$this->assertTrue($this->helper()->denyIP('203.0.113.5'));
			$this->assertTrue(is_link($this->dir.'/.htaccess'));
			$this->assertStringContainsString("-R '203.0.113.5'", file_get_contents($real));
		}
		finally
		{
			unlink($this->dir.'/.htaccess');
			unlink($real);
		}
	}

	public function testTheBlockSectionHasALimit()
	{
		$lines = array('<RequireAll>', 'Require all granted');
		for ($i = 0; $i < HtaccessHelper::MaxBlockLines; ++$i)
		{
			$lines[] = 'Require not ip 10.'.intdiv($i, 250).'.'.($i % 250).'.1';
		}
		$lines[] = '</RequireAll>';
		file_put_contents($this->dir.'/.htaccess', "# BEGIN BFStop Blocks\n".implode("\n", $lines)."\n# END BFStop Blocks\n");
		$this->assertFalse($this->helper(new RecordingLogger())->denyIP('203.0.113.5'));
		$this->assertStringNotContainsString('203.0.113.5', $this->content());
		// an address which is in there already is no new line
		$this->assertTrue($this->helper()->denyIP('10.0.0.1'));
	}

	public function testOnlyAddressesAreListed()
	{
		file_put_contents($this->dir.'/.htaccess', "# BEGIN BFStop Blocks\n<RequireAll>\nRequire all granted\n".
			"Require not ip 203.0.113.5\nRequire not ip \"><script>alert(1)</script>\nRequire not ip 2001:db8::/32\n".
			"Require not ip 203.0.113.0/99\n</RequireAll>\n# END BFStop Blocks\n");
		$this->assertSame(array('203.0.113.5', '2001:db8::/32'), $this->helper()->getDeniedIPs());
	}

	/**
	 * Apache combines the authorization directives at the top level of a
	 * section with an implicit <RequireAny>: a "Require all granted" in the
	 * block section would let everybody who isn't blocked past the other
	 * access controls of the directory (HTTP authentication, "Require ip").
	 * The section must only ever deny.
	 */
	public function testTheBlockSectionOnlyDenies()
	{
		$auth = "AuthType Basic\nAuthName \"Staff\"\nAuthUserFile /srv/.htpasswd\nRequire valid-user\n";
		file_put_contents($this->dir.'/.htaccess', $auth);
		$h = $this->helper();
		$h->denyIP('203.0.113.5');
		$h->denyIP('2001:db8:1::/56');
		$h->edit403Message('Blocked');
		$content = $this->content();
		$this->assertStringNotContainsString('Require all granted', $content);
		$this->assertStringNotContainsString('RequireAll', $content);
		$this->assertStringContainsString("<If \"-R '203.0.113.5' || -R '2001:db8:1::/56'\">\nRequire all denied\n</If>\n", $content);
		$this->assertStringEndsWith($auth, $content);
	}

	public function testTheSectionOfEarlierVersionsIsReplaced()
	{
		file_put_contents($this->dir.'/.htaccess', "# top\n# BEGIN BFStop Blocks\n<RequireAll>\nRequire all granted\n".
			"Require not ip 192.0.2.1\nRequire not ip 2001:db8::/32\nErrorDocument 403 \"Go away\"\nHeader set X-Hand 1\n".
			"</RequireAll>\n# END BFStop Blocks\n# bottom\n");
		$h = $this->helper();
		$this->assertTrue($h->hasLegacySection());
		$this->assertSame(array('192.0.2.1', '2001:db8::/32'), $h->getDeniedIPs());
		$this->assertTrue($h->upgradeFormat());
		$this->assertSame("# top\n# BEGIN BFStop Blocks\n<If \"-R '192.0.2.1' || -R '2001:db8::/32'\">\nRequire all denied\n</If>\n".
			"ErrorDocument 403 \"Go away\"\nHeader set X-Hand 1\n# END BFStop Blocks\n# bottom\n", $this->content());
		$this->assertFalse($h->hasLegacySection());
		$this->assertTrue($h->upgradeFormat(), 'nothing left to do');
	}

	public function testAnyChangeReplacesTheSectionOfEarlierVersions()
	{
		$legacy = "# BEGIN BFStop Blocks\n<RequireAll>\nRequire all granted\nRequire not ip 192.0.2.1\n</RequireAll>\n# END BFStop Blocks\n";
		foreach (array(
			'deny'           => function ($h) { return $h->denyIP('192.0.2.2'); },
			'undeny'         => function ($h) { return $h->undenyIP('192.0.2.1'); },
			'undeny absent'  => function ($h) { return $h->undenyIP('198.51.100.1'); },
			'403 message'    => function ($h) { return $h->edit403Message('Go away'); },
			'no 403 message' => function ($h) { return $h->remove403Message(); },
		) as $what => $change)
		{
			file_put_contents($this->dir.'/.htaccess', $legacy);
			$this->assertTrue($change($this->helper()), $what);
			$this->assertStringNotContainsString('Require all granted', $this->content(), $what);
			$this->assertFalse($this->helper()->hasLegacySection(), $what);
		}
	}

	public function testManyAddressesAreSplitIntoSeveralConditions()
	{
		$h = $this->helper();
		$addresses = array();
		for ($i = 1; $i <= HtaccessHelper::AddressesPerCondition * 2 + 1; ++$i)
		{
			$addresses[] = '198.51.'.intdiv($i, 250).'.'.($i % 250);
		}
		foreach ($addresses as $address)
		{
			$h->denyIP($address);
		}
		$this->assertSame(3, substr_count($this->content(), '<If '));
		$this->assertSame(3, substr_count($this->content(), "Require all denied\n</If>"));
		// Apache reads configuration lines of up to 8 KB
		$this->assertLessThan(8192, max(array_map('strlen', explode("\n", $this->content()))));
		$this->assertSame($addresses, $h->getDeniedIPs());
	}

	/**
	 * A file saved with Windows line ends (an FTP upload in ASCII mode) has a
	 * \r at the end of every line: its blocks must still be listed and
	 * removable, or the web server would keep them for ever.
	 */
	public function testWindowsLineEnds()
	{
		file_put_contents($this->dir.'/.htaccess', "RewriteEngine On\r\n# BEGIN BFStop Blocks\r\n<If \"-R '192.0.2.9'\">\r\n".
			"Require all denied\r\n</If>\r\n# END BFStop Blocks\r\nRewriteRule ^a$ b\r\n");
		$h = $this->helper();
		$this->assertSame(array('192.0.2.9'), $h->getDeniedIPs());
		$this->assertTrue($h->undenyIP('192.0.2.9'));
		$this->assertSame(array(), $h->getDeniedIPs());
		$this->assertSame("RewriteEngine On\r\n# BEGIN BFStop Blocks\n# END BFStop Blocks\nRewriteRule ^a$ b\r\n", $this->content(),
			'the lines outside the section are left as they are');
	}
}
