<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Joomla\CMS\Factory;
use Joomla\CMS\Installer\InstallerAdapter;

/**
 * The plugin's installer script (updatescript.php), called the way Joomla's
 * installer calls it, against the installed plugin's row: what it does
 * depends on the version being replaced, which is in its manifest cache.
 */
class InstallerScriptTest extends IntegrationTestCase
{
	private $originalManifestCache;

	protected function setUp(): void
	{
		parent::setUp();
		require_once dirname(__DIR__, 2).'/updatescript.php';
		$this->originalManifestCache = $this->queryValue(
			"SELECT manifest_cache FROM #__extensions WHERE type='plugin' AND element='bfstop'");
		Factory::getApplication()->getMessageQueue(true);
	}

	protected function tearDown(): void
	{
		$this->setInstalledVersion(null);
		Factory::getApplication()->getMessageQueue(true);
	}

	private function setInstalledVersion($version)
	{
		$cache = $this->originalManifestCache;
		if ($version !== null)
		{
			$decoded = json_decode((string) $cache, true) ?: array();
			$decoded['version'] = $version;
			$cache = json_encode($decoded);
		}
		$this->db->setQuery('UPDATE #__extensions SET manifest_cache='.$this->db->quote($cache).
			" WHERE type='plugin' AND element='bfstop'");
		$this->db->execute();
	}

	private function script()
	{
		$adapter = $this->createMock(InstallerAdapter::class);
		$adapter->method('getName')->willReturn('plg_system_bfstop');
		$adapter->method('getManifest')->willReturn(simplexml_load_file(dirname(__DIR__, 2).'/bfstop.xml'));
		return array(new \PlgsystembfstopInstallerScript($adapter), $adapter);
	}

	private function messages()
	{
		return array_map(function ($message) { return $message['message']; },
			Factory::getApplication()->getMessageQueue(true));
	}

	private function updateHintShown($fromVersion)
	{
		$this->setInstalledVersion($fromVersion);
		list($script, $adapter) = $this->script();
		$this->assertTrue($script->preflight('update', $adapter));
		$script->postflight('update', $adapter);
		$hint = strip_tags(\Joomla\CMS\Language\Text::sprintf('PLG_SYSTEM_BFSTOP_UPDATE_2_0_0_HINT', ''));
		foreach ($this->messages() as $message)
		{
			if (strip_tags($message) === $hint)
			{
				return true;
			}
		}
		return false;
	}

	public function testSettingsMovedHintOnlyForUpdatesFromBefore200()
	{
		Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
		$this->assertTrue($this->updateHintShown('1.5.2'));
		$this->assertFalse($this->updateHintShown('2.0.0'), 'the settings did not move again');
		$this->assertFalse($this->updateHintShown('2.0.0-rc1'), 'a test release of 2.0.0 had them where they are');
	}

	/**
	 * Runs the update of the installed plugin from $fromVersion, whose stored
	 * settings are $params; returns the settings afterwards
	 */
	private function update($fromVersion, array $params)
	{
		$this->setInstalledVersion($fromVersion);
		$this->setPluginParams(json_encode($params));
		list($script, $adapter) = $this->script();
		$this->assertTrue($script->preflight('update', $adapter));
		$script->update($adapter);
		$script->postflight('update', $adapter);
		return json_decode($this->getPluginParams(), true);
	}

	public function testUpdateFromBefore200ProtectsTheApi()
	{
		Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
		$hint = strip_tags(\Joomla\CMS\Language\Text::sprintf('PLG_SYSTEM_BFSTOP_UPDATE_2_0_0_API_HINT', ''));
		$hintShown = function () use ($hint)
		{
			return in_array($hint, array_map('strip_tags', $this->messages()), true);
		};
		$original = $this->getPluginParams();
		try
		{
			// the frontend/backend setting of 1.x knew nothing of the API
			$params = $this->update('1.5.2', array('blockEnabled' => '1', 'enabledForOrigin' => '2'));
			$this->assertSame(6, $params['enabledForOrigin'], 'backend only became backend and API');
			$this->assertSame('full', $params['blockMode']);
			$this->assertTrue($hintShown());
			// never saved: its default protects the API anyway
			$params = $this->update('1.5.2', array('blockEnabled' => '1'));
			$this->assertArrayNotHasKey('enabledForOrigin', $params);
			$this->assertTrue($hintShown());
			// a later update leaves the choice alone
			$params = $this->update('2.0.0', array('blockMode' => 'full', 'enabledForOrigin' => 3));
			$this->assertSame(3, $params['enabledForOrigin']);
			$this->assertFalse($hintShown());
		}
		finally
		{
			$this->setPluginParams($original);
		}
	}

	public function testRefusesToReplaceANewerVersion()
	{
		$this->setInstalledVersion('99.0.0');
		list($script, $adapter) = $this->script();
		$this->assertFalse($script->preflight('update', $adapter));
	}

	public function testWhitelistTableIsRenamedBeforeTheUpdateSql()
	{
		// new installations of 1.4.2 kept the old table name; the update SQL
		// of 2.0.0 (run between preflight and update) changes the allowlist
		if ($this->db->getServerType() !== 'mysql')
		{
			$this->markTestSkipped('only MySQL installations can be that old');
		}
		$this->db->setQuery('RENAME TABLE #__bfstop_allowlist TO #__bfstop_whitelist');
		$this->db->execute();
		try
		{
			$this->setInstalledVersion('1.4.2');
			list($script, $adapter) = $this->script();
			$this->assertTrue($script->preflight('update', $adapter));
			$tables = array_map('strtolower', $this->db->getTableList());
			$this->assertContains(strtolower($this->db->getPrefix().'bfstop_allowlist'), $tables);
			$this->assertNotContains(strtolower($this->db->getPrefix().'bfstop_whitelist'), $tables);
		}
		finally
		{
			$tables = array_map('strtolower', $this->db->getTableList());
			if (in_array(strtolower($this->db->getPrefix().'bfstop_whitelist'), $tables, true))
			{
				$this->db->setQuery('RENAME TABLE #__bfstop_whitelist TO #__bfstop_allowlist');
				$this->db->execute();
			}
		}
	}

	/**
	 * Versions up to 2.0.0 wrote a block section with "Require all granted"
	 * into the .htaccess file, which Apache ORs with the directory's other
	 * access controls: the update replaces it, whatever the blocking mode is
	 * now, and says so if it can't.
	 */
	public function testUpdateReplacesTheBlockSectionOfEarlierVersions()
	{
		Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
		$dir = sys_get_temp_dir().'/bfstop-update-htaccess-'.bin2hex(random_bytes(4));
		mkdir($dir);
		$original = $this->getPluginParams();
		$legacy = "# BEGIN BFStop Blocks\n<RequireAll>\nRequire all granted\nRequire not ip 192.0.2.1\n".
			"ErrorDocument 403 \"Go away\"\n</RequireAll>\n# END BFStop Blocks\n\nAuthType Basic\nRequire valid-user\n";
		$notRewritten = strip_tags(\Joomla\CMS\Language\Text::sprintf('PLG_SYSTEM_BFSTOP_UPDATE_HTACCESS_NOT_REWRITTEN', $dir.'/.htaccess'));
		try
		{
			file_put_contents($dir.'/.htaccess', $legacy);
			$this->update('2.0.0', array('blockMode' => 'full', 'htaccessPath' => $dir));
			$this->assertSame("# BEGIN BFStop Blocks\n<If \"-R '192.0.2.1'\">\nRequire all denied\n</If>\nErrorDocument 403 \"Go away\"\n".
				"# END BFStop Blocks\n\nAuthType Basic\nRequire valid-user\n", file_get_contents($dir.'/.htaccess'));
			$this->assertNotContains($notRewritten, array_map('strip_tags', $this->messages()));

			// nothing to do for a section of the current form, or no file
			$current = file_get_contents($dir.'/.htaccess');
			$this->update('2.0.0', array('blockMode' => 'htaccess', 'htaccessPath' => $dir));
			$this->assertSame($current, file_get_contents($dir.'/.htaccess'));
			$this->assertTrue(\PlgsystembfstopInstallerScript::replaceLegacyHtaccessSection($dir.'/none/.htaccess'));

			if (!function_exists('posix_geteuid') || posix_geteuid() !== 0)
			{
				file_put_contents($dir.'/.htaccess', $legacy);
				chmod($dir.'/.htaccess', 0444);
				chmod($dir, 0555);
				$this->update('2.0.0', array('blockMode' => 'full', 'htaccessPath' => $dir));
				$this->assertContains($notRewritten, array_map('strip_tags', $this->messages()));
			}
		}
		finally
		{
			@chmod($dir, 0755);
			@chmod($dir.'/.htaccess', 0644);
			@unlink($dir.'/.htaccess');
			@rmdir($dir);
			$this->setPluginParams($original);
		}
	}
}
