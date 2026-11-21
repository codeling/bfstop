<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Helper\NginxDenyFile;
use Codeling\Library\Bfstop\Repository\Repositories;
use Joomla\Registry\Registry;

/**
 * The file of "deny" lines for nginx (issue #285): what goes into it, which
 * files it may overwrite, and that it follows the block list.
 */
class NginxDenyFileTest extends IntegrationTestCase
{
	private string $dir;

	protected function setUp(): void
	{
		parent::setUp();
		$this->dir = sys_get_temp_dir().'/bfstop-nginx-'.bin2hex(random_bytes(4));
		mkdir($this->dir);
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir.'/*') ?: array() as $file)
		{
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	private function block($ip, $minutesAgo = 0, $duration = 60)
	{
		return (int) $this->insert('#__bfstop_bannedip', array('ipaddress' => $ip,
			'crdate' => self::minutesAgo($minutesAgo), 'duration' => $duration), 'id');
	}

	public function testContent()
	{
		$this->assertSame(NginxDenyFile::Header."\ndeny 203.0.113.5;\ndeny 2001:db8:1:200::/56;\n",
			NginxDenyFile::content(array('203.0.113.5', '2001:db8:1:200::/56', '203.0.113.5',
				// only addresses and networks get into the server's configuration
				'203.0.113.6; allow all', "203.0.113.7\ninclude /etc/passwd", '')));
		$this->assertSame(NginxDenyFile::Header."\n", NginxDenyFile::content(array()));
	}

	public function testOnlyItsOwnFilesAreOverwritten()
	{
		$this->assertNull(NginxDenyFile::problem($this->dir.'/bfstop.conf'), 'a new file');
		$this->assertSame('path', NginxDenyFile::problem('bfstop.conf'), 'relative');
		$this->assertSame('path', NginxDenyFile::problem($this->dir.'/configuration.php'), 'no .conf');
		$this->assertSame('path', NginxDenyFile::problem($this->dir.'/.conf'));
		$this->assertSame('path', NginxDenyFile::problem('phar://'.$this->dir.'/x.conf'));
		$this->assertSame('directory', NginxDenyFile::problem($this->dir.'/none/bfstop.conf'));

		file_put_contents($this->dir.'/site.conf', "server { listen 80; }\n");
		$this->assertSame('foreign', NginxDenyFile::problem($this->dir.'/site.conf'));
		$this->assertFalse((new NginxDenyFile($this->dir.'/site.conf', $this->logger))->write(array('203.0.113.5')));
		$this->assertSame("server { listen 80; }\n", file_get_contents($this->dir.'/site.conf'), 'left as it was');
		$this->logger->errors = array();

		$file = new NginxDenyFile($this->dir.'/bfstop.conf', $this->logger);
		$this->assertTrue($file->write(array('203.0.113.5')));
		$this->assertSame(NginxDenyFile::Header."\ndeny 203.0.113.5;\n", file_get_contents($this->dir.'/bfstop.conf'));
		$this->assertNull(NginxDenyFile::problem($this->dir.'/bfstop.conf'), 'its own file');
		$this->assertTrue($file->write(array()));
		$this->assertSame(NginxDenyFile::Header."\n", file_get_contents($this->dir.'/bfstop.conf'));
		$this->assertSame(array('bfstop.conf', 'site.conf'), array_map('basename', glob($this->dir.'/*')),
			'no temporary file left');
	}

	public function testItFollowsTheBlockList()
	{
		$this->block('203.0.113.1', 10);
		$this->block('2001:db8:1:200::/56', 5);
		$this->block('203.0.113.2', 120, 60);
		$lifted = $this->block('203.0.113.3');
		$this->insert('#__bfstop_unblock', array('block_id' => $lifted, 'source' => 0, 'crdate' => self::minutesAgo(0)));
		$this->block('203.0.113.4', 60 * 24 * 365, 0);
		// a network with an address of the allow list: nginx would turn it away
		$this->block('198.51.100.0/24');
		$this->insert('#__bfstop_allowlist', array('ipaddress' => '198.51.100.7', 'notes' => ''));

		$repositories = new Repositories($this->logger);
		$file = new NginxDenyFile($this->dir.'/bfstop.conf', $this->logger);
		$this->assertTrue($file->sync($repositories, true));
		$this->assertSame(NginxDenyFile::Header."\ndeny 203.0.113.4;\ndeny 2001:db8:1:200::/56;\ndeny 203.0.113.1;\n",
			file_get_contents($this->dir.'/bfstop.conf'), 'the active blocks, the newest first');

		// another blocking mode: nginx blocks nobody
		$this->assertTrue($file->sync($repositories, false));
		$this->assertSame(NginxDenyFile::Header."\n", file_get_contents($this->dir.'/bfstop.conf'));
		$this->assertTrue((new NginxDenyFile($this->dir.'/new.conf'))->sync($repositories, false));
		$this->assertFileDoesNotExist($this->dir.'/new.conf', 'not made for nothing');

		// from the settings
		$settings = new Registry(array('blockMode' => 'full', 'nginxDenyFile' => $this->dir.'/bfstop.conf'));
		$this->assertTrue(NginxDenyFile::syncForSettings($settings, $repositories));
		$this->assertStringContainsString('deny 203.0.113.1;', file_get_contents($this->dir.'/bfstop.conf'));
		$this->assertNull(NginxDenyFile::syncForSettings(new Registry(array('blockMode' => 'full')), $repositories),
			'no file in the settings');
		$this->assertTrue(NginxDenyFile::syncForSettings(new Registry(array('blockMode' => 'loginonly',
			'nginxDenyFile' => $this->dir.'/bfstop.conf')), $repositories));
		$this->assertSame(NginxDenyFile::Header."\n", file_get_contents($this->dir.'/bfstop.conf'), 'Login Only');
	}
}
