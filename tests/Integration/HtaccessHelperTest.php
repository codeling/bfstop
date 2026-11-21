<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Helper\HtaccessHelper;
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

	/**
	 * The <If> line the section has for $conditions ("-R '...' || ..."): the
	 * tests run as a site at the root of the server.
	 */
	private static function ifLine($conditions)
	{
		return '<If "('.$conditions.') && !(%{REQUEST_URI} == \'/index.php\' && %{QUERY_STRING} =~ /'.
			HtaccessHelper::UnblockQueryPattern.'/)">';
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
		$this->assertSame(HtaccessHelper::ServerNginx, $req['server']);
		$this->assertTrue($req['found']);
		$this->assertTrue($req['readable']);
		$this->assertTrue($req['writeable']);
	}

	public function testWebServer()
	{
		foreach (array('Apache/2.4.58 (Ubuntu)' => HtaccessHelper::ServerApache, 'Apache' => HtaccessHelper::ServerApache,
			'nginx/1.25.4' => HtaccessHelper::ServerNginx, 'nginx' => HtaccessHelper::ServerNginx,
			'LiteSpeed' => HtaccessHelper::ServerLiteSpeed, 'Microsoft-IIS/10.0' => HtaccessHelper::ServerOther,
			'PHP 8.3.6 Development Server' => HtaccessHelper::ServerOther, '' => HtaccessHelper::ServerOther) as $software => $server)
		{
			$this->assertSame($server, HtaccessHelper::webServer($software), $software);
		}
	}

	public function testProbe()
	{
		$token = str_repeat('0123456789abcdef', 2);
		$this->assertSame(array("<If \"-R '192.0.2.1' || %{QUERY_STRING} == 'deny=$token'\">", 'Require all denied', '</If>'),
			HtaccessHelper::probeLines($token));
		$probe = $this->dir.'/probe';
		$this->assertTrue(HtaccessHelper::writeProbe($probe, $token));
		$this->assertSame(implode("\n", HtaccessHelper::probeLines($token))."\n", file_get_contents($probe.'/.htaccess'));
		$this->assertSame($token, file_get_contents($probe.'/'.HtaccessHelper::ProbeFile));
		$this->assertFalse(HtaccessHelper::writeProbe($probe, $token), 'not into a directory which exists');
		HtaccessHelper::removeProbe($probe);
		$this->assertDirectoryDoesNotExist($probe);
		foreach (array('', 'xyz', "abc'def0123456789", str_repeat('a', 65)) as $bad)
		{
			try
			{
				HtaccessHelper::probeLines($bad);
				$this->fail('taken: '.$bad);
			}
			catch (\InvalidArgumentException $e)
			{
				$this->assertStringContainsString('hex digits', $e->getMessage());
			}
		}
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
			"# BEGIN BFStop Blocks\n".self::ifLine("-R '203.0.113.5'")."\nRequire all denied\n</If>\n# END BFStop Blocks\n\n",
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

	public function testSeveralSectionsBecomeOne()
	{
		// not meant to happen (a file merged by hand, say); the addresses of
		// all of them are kept, and what is between and around them
		file_put_contents($this->dir.'/.htaccess', "A\n# BEGIN BFStop Blocks\nRequire not ip 203.0.113.1\n# END BFStop Blocks\n".
			"M\n# BEGIN BFStop Blocks\nRequire not ip 203.0.113.2\n# END BFStop Blocks\nZ\n");
		$this->assertTrue($this->helper()->denyIP('203.0.113.3'));
		$this->assertSame("A\n# BEGIN BFStop Blocks\n".
			self::ifLine("-R '203.0.113.1' || -R '203.0.113.2' || -R '203.0.113.3'")."\nRequire all denied\n</If>\n".
			"# END BFStop Blocks\nM\nZ\n", $this->content());
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
		$content = $this->content();
		$this->assertStringNotContainsString('Require all granted', $content);
		$this->assertStringNotContainsString('RequireAll', $content);
		$this->assertStringContainsString(self::ifLine("-R '203.0.113.5' || -R '2001:db8:1::/56'")."\nRequire all denied\n</If>\n", $content);
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
		$this->assertSame("# top\n# BEGIN BFStop Blocks\n".self::ifLine("-R '192.0.2.1' || -R '2001:db8::/32'")."\nRequire all denied\n</If>\n".
			"ErrorDocument 403 \"Go away\"\nHeader set X-Hand 1\n# END BFStop Blocks\n# bottom\n", $this->content());
		$this->assertFalse($h->hasLegacySection());
		$this->assertTrue($h->upgradeFormat(), 'nothing left to do');
	}

	public function testBlocksWrittenByHandAreKeptAsTheyAre()
	{
		// an <If> of somebody else's in the section is not one of the
		// plugin's: neither its condition nor its lines are taken apart
		$hand = array(
			'<If "%{HTTP_HOST} == \'old.example.org\'">',
			'Require all denied',
			'</If>',
			'<If "-R \'198.51.100.0/24\' && %{REQUEST_URI} =~ m#^/administrator#">',
			'  <If "%{HTTP_COOKIE} =~ /staff=1/">',
			'    Require all granted',
			'  </If>',
			'  Require all denied',
			'</If>',
			'<IfModule mod_headers.c>',
			'Header set X-Hand 1',
			'</IfModule>',
		);
		file_put_contents($this->dir.'/.htaccess', "# BEGIN BFStop Blocks\n".implode("\n", $hand)."\n# END BFStop Blocks\n");
		$h = $this->helper();
		$this->assertSame(array(), $h->getDeniedIPs(), 'the hand-written conditions name no blocks');
		$this->assertTrue($h->denyIP('203.0.113.5'));
		$this->assertTrue($h->denyIP('203.0.113.6'));
		$this->assertTrue($h->undenyIP('203.0.113.5'));
		$this->assertSame(array('203.0.113.6'), $h->getDeniedIPs());
		$content = $this->content();
		$this->assertStringContainsString(implode("\n", $hand)."\n# END BFStop Blocks", $content);
		$this->assertStringContainsString(self::ifLine("-R '203.0.113.6'")."\nRequire all denied\n</If>\n", $content);
		$this->assertSame(4, substr_count($content, '<If '), 'the three <If> written by hand and the one of the block');
	}

	public function testAnyChangeReplacesTheSectionOfEarlierVersions()
	{
		$legacy = "# BEGIN BFStop Blocks\n<RequireAll>\nRequire all granted\nRequire not ip 192.0.2.1\n</RequireAll>\n# END BFStop Blocks\n";
		foreach (array(
			'deny'           => function ($h) { return $h->denyIP('192.0.2.2'); },
			'undeny'         => function ($h) { return $h->undenyIP('192.0.2.1'); },
			'undeny absent'  => function ($h) { return $h->undenyIP('198.51.100.1'); },
			'upgrade'        => function ($h) { return $h->upgradeFormat(); },
		) as $what => $change)
		{
			file_put_contents($this->dir.'/.htaccess', $legacy);
			$this->assertTrue($change($this->helper()), $what);
			$this->assertStringNotContainsString('Require all granted', $this->content(), $what);
			$this->assertFalse($this->helper()->hasLegacySection(), $what);
		}
	}

	/**
	 * The web server refuses every request of a blocked address: the link of
	 * an unblock email has to get through to Joomla, which decides whether
	 * it unblocks anything.
	 */
	public function testTheLinkOfAnUnblockEmailGetsThrough()
	{
		$this->assertSame('/index.php', HtaccessHelper::unblockPagePath());
		$link = \Codeling\Library\Bfstop\Helper\TokenHelper::unblockLink(sha1('token'));
		$this->assertSame(1, preg_match('#'.str_replace('#', '\\#', HtaccessHelper::UnblockQueryPattern).'#',
			(string) parse_url($link, PHP_URL_QUERY)), $link);
		$this->assertSame(HtaccessHelper::unblockPagePath(), parse_url($link, PHP_URL_PATH));
		foreach (array('', '&task=user.login', '&option=com_users') as $more)
		{
			$query = 'option=com_bfstop&view=tokenunblock&token='.sha1('token').$more;
			$this->assertSame($more === '' ? 1 : 0, preg_match('#'.HtaccessHelper::UnblockQueryPattern.'#', $query), $query);
		}
		$this->assertSame(0, preg_match('#'.HtaccessHelper::UnblockQueryPattern.'#',
			'option=com_bfstop&view=tokenunblock&token=xyz'));
	}

	/**
	 * A section written before the unblock page was let through: the daily
	 * maintenance writes it in the current form.
	 */
	public function testASectionWithoutTheUnblockPageIsWrittenInTheCurrentForm()
	{
		file_put_contents($this->dir.'/.htaccess', "# BEGIN BFStop Blocks\n<If \"-R '192.0.2.1'\">\nRequire all denied\n</If>\n".
			"ErrorDocument 403 \"Go away\"\n# END BFStop Blocks\nAuthType Basic\n");
		$h = $this->helper();
		$this->assertTrue($h->upgradeFormat());
		$current = "# BEGIN BFStop Blocks\n".self::ifLine("-R '192.0.2.1'")."\nRequire all denied\n</If>\n".
			"ErrorDocument 403 \"Go away\"\n# END BFStop Blocks\nAuthType Basic\n";
		$this->assertSame($current, $this->content());
		$mtime = filemtime($this->dir.'/.htaccess');
		clearstatcache();
		touch($this->dir.'/.htaccess', $mtime - 100);
		$this->assertTrue($h->upgradeFormat());
		clearstatcache();
		$this->assertSame($mtime - 100, filemtime($this->dir.'/.htaccess'), 'a section in the current form is left alone');
		$this->assertSame($current, $this->content());
	}

	public function testRemovingSeveralAddressesAtOnce()
	{
		$h = $this->helper();
		$this->assertSame(0, $h->removeAddresses(array('203.0.113.5')), 'no file');
		$this->assertFileDoesNotExist($this->dir.'/.htaccess');
		foreach (array('203.0.113.5', '203.0.113.6', '2001:db8:1::/56', '198.51.100.7') as $ip)
		{
			$h->denyIP($ip);
		}
		$this->assertSame(2, $h->removeAddresses(array('203.0.113.6', '2001:db8:1::/56', '192.0.2.1')));
		$this->assertSame(array('203.0.113.5', '198.51.100.7'), $h->getDeniedIPs());
		$this->assertSame(0, $h->removeAddresses(array('192.0.2.1')));
	}

	/**
	 * A block of the plugin from the time the file blocked: once it doesn't,
	 * all of them come out, active or not; with blocking through the file,
	 * only those whose blocks are over. What was added by hand stays.
	 */
	public function testStaleBlocksDependOnWhetherTheFileBlocks()
	{
		$this->insert('#__bfstop_bannedip', array('ipaddress' => '203.0.113.5', 'crdate' => self::minutesAgo(120), 'duration' => 60));
		$this->insert('#__bfstop_bannedip', array('ipaddress' => '203.0.113.6', 'crdate' => self::minutesAgo(10), 'duration' => 60));
		$this->insert('#__bfstop_bannedip', array('ipaddress' => '2001:db8:1::/56', 'crdate' => self::minutesAgo(10), 'duration' => 0));
		$db = (new Repositories($this->logger))->blocks();
		$h = $this->helper();
		$this->assertSame(0, $h->removeStaleBlocks($db, false), 'no file');
		$this->assertFileDoesNotExist($this->dir.'/.htaccess');
		$deny = function () use ($h)
		{
			foreach (array('203.0.113.5', '203.0.113.6', '2001:db8:1::/56', '198.51.100.7') as $ip)
			{
				$h->denyIP($ip);                     // .7: added by hand
			}
		};
		$deny();
		$this->assertSame(1, $h->removeStaleBlocks($db, true));
		$this->assertSame(array('203.0.113.6', '2001:db8:1::/56', '198.51.100.7'), $h->getDeniedIPs());
		$deny();
		$this->assertSame(3, $h->removeStaleBlocks($db, false));
		$this->assertSame(array('198.51.100.7'), $h->getDeniedIPs());
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

	/**
	 * What the file gets for a block: an IPv6 client tracked by its /56 (see
	 * IpHelper::trackedAddress()) gets its /64, everything else what it is
	 * tracked as.
	 */
	public function testAnIpv6ClientsEntryIsItsSlash64()
	{
		$this->assertSame('2001:db8:1:2a::/64', HtaccessHelper::entryFor('2001:db8:1::/56', '2001:db8:1:2a::5'));
		$this->assertSame('2001:db8:1:2a::/64', HtaccessHelper::entryFor('2001:db8::/32', '2001:db8:1:2a:ffff::1'));
		// the client is not known, or not in the network
		$this->assertSame('2001:db8:1::/56', HtaccessHelper::entryFor('2001:db8:1::/56', null));
		$this->assertSame('2001:db8:1::/56', HtaccessHelper::entryFor('2001:db8:1::/56', '2001:db8:9::1'));
		// tracked by a /64 or less, or not aggregated (6to4), or IPv4
		$this->assertSame('2001:db8:1:2a::/64', HtaccessHelper::entryFor('2001:db8:1:2a::/64', '2001:db8:1:2a::5'));
		$this->assertSame('2001:db8:1:2a:5::/80', HtaccessHelper::entryFor('2001:db8:1:2a:5::/80', '2001:db8:1:2a:5::1'));
		$this->assertSame('2002:cb00:7105::1', HtaccessHelper::entryFor('2002:cb00:7105::1', '2002:cb00:7105::1'));
		$this->assertSame('203.0.113.5', HtaccessHelper::entryFor('203.0.113.5', '203.0.113.5'));
		$this->assertSame('203.0.113.0/24', HtaccessHelper::entryFor('203.0.113.0/24', '203.0.113.5'));

		$this->assertTrue(HtaccessHelper::isEntryOf('2001:db8:1::/56', '2001:db8:1::/56'));
		$this->assertTrue(HtaccessHelper::isEntryOf('2001:db8:1:2a::/64', '2001:db8:1::/56'));
		$this->assertTrue(HtaccessHelper::isEntryOf('203.0.113.5', '203.0.113.5'));
		// written by an earlier version for a client the web server reported
		// IPv4-mapped, whose block is IPv4 now
		$this->assertTrue(HtaccessHelper::isEntryOf('::ffff:203.0.113.5', '203.0.113.5'));
		$this->assertFalse(HtaccessHelper::isEntryOf('::ffff:203.0.113.6', '203.0.113.5'));
		$this->assertFalse(HtaccessHelper::isEntryOf('2001:db8:2:2a::/64', '2001:db8:1::/56'), 'another network');
		$this->assertFalse(HtaccessHelper::isEntryOf('2001:db8:1:2a::/80', '2001:db8:1::/56'), 'no /64: written by hand');
		$this->assertFalse(HtaccessHelper::isEntryOf('2001:db8:1:2a::5', '2001:db8:1::/56'));
		$this->assertFalse(HtaccessHelper::isEntryOf('2001:db8:1:2a::/64', '2001:db8:1:2a::/64/'), 'garbage');
		$this->assertFalse(HtaccessHelper::isEntryOf('203.0.113.5', '203.0.113.0/24'));
	}

	/**
	 * The /64 entries come out of the file with the block of their network -
	 * also the /56 entries the file got from earlier versions - unless
	 * another block which covers them is still active.
	 */
	public function testTheSlash64EntriesComeOutWithTheirNetworksBlock()
	{
		$block = function ($address, $minutesAgo, $duration)
		{
			return $this->insert('#__bfstop_bannedip', array('ipaddress' => $address,
				'crdate' => self::minutesAgo($minutesAgo), 'duration' => $duration), 'id');
		};
		$block('2001:db8:1::/56', 120, 60);      // over
		$block('2001:db8:1:2c::/64', 0, 60);     // made by hand, active
		$block('2001:db8:3::/56', 0, 60);        // active
		$h = $this->helper();
		foreach (array('2001:db8:1:2a::/64', '2001:db8:1::/56', '2001:db8:1:2b::/80', '2001:db8:1:2c::/64',
			'2001:db8:3:1::/64', '2001:db8:4:1::/64') as $entry)
		{
			$this->assertTrue($h->denyIP($entry));
		}
		$this->assertSame(2, $h->removeLiftedBlocks((new Repositories($this->logger))->blocks()));
		$this->assertSame(array('2001:db8:1:2b::/80', '2001:db8:1:2c::/64', '2001:db8:3:1::/64', '2001:db8:4:1::/64'),
			$h->getDeniedIPs(), 'the /64 of the block which is over and its /56 came out; '.
			'what was written by hand, is still blocked or has no block stays');

		// a file which doesn't block any more loses every entry of a block
		$this->assertSame(2, $h->removeDatabaseBlocks((new Repositories($this->logger))->blocks()));
		$this->assertSame(array('2001:db8:1:2b::/80', '2001:db8:4:1::/64'), $h->getDeniedIPs());
	}
}
