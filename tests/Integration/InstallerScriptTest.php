<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
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
	private $originalPluginParams;

	protected function setUp(): void
	{
		parent::setUp();
		require_once BFSTOP_PLUGIN_ROOT.'/updatescript.php';
		$this->originalManifestCache = $this->queryValue(
			"SELECT manifest_cache FROM #__extensions WHERE type='plugin' AND folder='system' AND element='bfstop'");
		$this->originalPluginParams = $this->pluginParams();
		Factory::getApplication()->getMessageQueue(true);
	}

	protected function tearDown(): void
	{
		$this->setInstalledVersion(null);
		$this->setPluginParams($this->originalPluginParams);
		Factory::getApplication()->getMessageQueue(true);
	}

	/** The plugin's own params, where versions before 2.0.0 kept the settings. */
	private function pluginParams()
	{
		return $this->queryValue("SELECT params FROM #__extensions WHERE type='plugin' AND folder='system' AND element='bfstop'");
	}

	private function setPluginParams($params)
	{
		$this->db->setQuery('UPDATE #__extensions SET params='.$this->db->quote($params).
			" WHERE type='plugin' AND folder='system' AND element='bfstop'");
		$this->db->execute();
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
			" WHERE type='plugin' AND folder='system' AND element='bfstop'");
		$this->db->execute();
	}

	private function script()
	{
		$adapter = $this->createMock(InstallerAdapter::class);
		$adapter->method('getName')->willReturn('plg_system_bfstop');
		$adapter->method('getManifest')->willReturn(simplexml_load_file(BFSTOP_PLUGIN_ROOT.'/bfstop.xml'));
		return array(new \PlgsystembfstopInstallerScript($adapter), $adapter);
	}

	private function messages()
	{
		return array_map(function ($message) { return $message['message']; },
			Factory::getApplication()->getMessageQueue(true));
	}

	/**
	 * Whether the message about the setup assistant (of an update, see
	 * setupMessage()) is shown after the update of the installed plugin
	 * from $fromVersion, with the setup state $setup.
	 */
	private function setupMessageShown($fromVersion, $setup)
	{
		$this->db->setQuery("DELETE FROM #__bfstop_state WHERE name='setup'")->execute();
		if ($setup !== null)
		{
			\PlgsystembfstopInstallerScript::writeSetupState($this->db, $setup);
		}
		$this->setInstalledVersion($fromVersion);
		list($script, $adapter) = $this->script();
		$this->assertTrue($script->preflight('update', $adapter));
		$script->update($adapter);
		$script->postflight('update', $adapter);
		$expected = strip_tags(\Joomla\CMS\Language\Text::sprintf('PLG_SYSTEM_BFSTOP_SETUP_UPDATED', ''));
		return in_array($expected, array_map('strip_tags', $this->messages()), true);
	}

	/**
	 * After an update, the setup assistant is what to look at - until it has
	 * been completed: the update from 1.5.2, and any later one while it
	 * hasn't. Its message replaces the hints of the settings which moved and
	 * of the API, which are the assistant's overview now.
	 */
	public function testSetupMessageWhileTheSetupIsNotComplete()
	{
		Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
		$original = $this->getSettings();
		$pluginParams = $this->pluginParams();
		try
		{
			$this->assertTrue($this->setupMessageShown('1.5.2', null));
			$this->assertTrue($this->setupMessageShown('2.0.0', array('mode' => 'install')), 'the setup is still open');
			$this->assertFalse($this->setupMessageShown('2.0.0', array('mode' => 'upgrade', 'completed' => time())),
				'the setup is complete');
		}
		finally
		{
			$this->setSettings($original);
			$this->setPluginParams($pluginParams);
		}
	}

	/** A new installation says that the plugin isn't active yet, and leaves it disabled. */
	public function testInstallationLeavesThePluginDisabled()
	{
		Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
		$enabled = "SELECT enabled FROM #__extensions WHERE type='plugin' AND folder='system' AND element='bfstop'";
		$before = (int) $this->queryValue($enabled);
		try
		{
			$this->db->setQuery("UPDATE #__extensions SET enabled=0 WHERE type='plugin' AND folder='system' AND element='bfstop'")->execute();
			list($script, $adapter) = $this->script();
			$this->assertTrue($script->install($adapter));
			$script->postflight('install', $adapter);
			$this->assertSame(0, (int) $this->queryValue($enabled), 'the setup assistant activates it');
			$this->assertSame(array('mode' => 'install'), \PlgsystembfstopInstallerScript::readSetupState($this->db));
			$messages = array_map('strip_tags', $this->messages());
			$this->assertContains(strip_tags(\Joomla\CMS\Language\Text::sprintf('PLG_SYSTEM_BFSTOP_SETUP_INSTALLED', '')), $messages);
		}
		finally
		{
			$this->db->setQuery("UPDATE #__extensions SET enabled=".$before." WHERE type='plugin' AND folder='system' AND element='bfstop'")->execute();
		}
	}

	/**
	 * An update through the browser whose request came through a proxy
	 * disables the plugin (it would block everybody), and says so; one from
	 * the command line does where Joomla's "Behind Load Balancer" is on.
	 * The state of the setup says why, with the scenario and the names of
	 * the headers (no address). An update without proxy signals leaves it
	 * enabled.
	 */
	public function testAnUpdateBehindAProxyDisablesThePlugin()
	{
		Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
		$enabled = "SELECT enabled FROM #__extensions WHERE type='plugin' AND folder='system' AND element='bfstop'";
		$before = (int) $this->queryValue($enabled);
		$server = $_SERVER;
		$original = $this->getSettings();
		$pluginParams = $this->pluginParams();
		try
		{
			// without proxy signals
			$this->update('1.5.2', array('blockEnabled' => '1'));
			$this->assertSame(1, (int) $this->queryValue($enabled));
			$setup = \PlgsystembfstopInstallerScript::readSetupState($this->db);
			$this->assertSame(array('mode' => 'upgrade', 'from' => '1.5.2', 'scenario' => 'A', 'headers' => array()), $setup);

			// a request from a load balancer of the private network, with X-Forwarded-For
			$this->db->setQuery("DELETE FROM #__bfstop_state WHERE name='setup'")->execute();
			$_SERVER['REMOTE_ADDR'] = '10.0.0.5';
			$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.7';
			$this->update('1.5.2', array('blockEnabled' => '1'));
			$this->assertSame(0, (int) $this->queryValue($enabled), 'disabled by the update');
			$setup = \PlgsystembfstopInstallerScript::readSetupState($this->db);
			$this->assertSame('proxy', $setup['disabled']);
			$this->assertSame('B', $setup['scenario']);
			$this->assertSame(array('HTTP_X_FORWARDED_FOR'), $setup['headers']);
			$this->assertStringNotContainsString('203.0.113.7', json_encode($setup));
			$this->assertStringNotContainsString('10.0.0.5', json_encode($setup));
			$disabled = strip_tags(\Joomla\CMS\Language\Text::sprintf('PLG_SYSTEM_BFSTOP_SETUP_DISABLED_PROXY', ''));
			$queue = Factory::getApplication()->getMessageQueue(true);
			$this->assertNotEmpty(array_filter($queue, fn ($m) => strip_tags($m['message']) === $disabled && $m['type'] === 'error'));
			// the library reads what the update wrote
			$state = \Codeling\Library\Bfstop\Service\Setup\SetupState::load((new Repositories($this->logger))->state());
			$this->assertSame('upgrade', $state->mode());
			$this->assertSame('1.5.2', $state->from());
			$this->assertSame('proxy', $state->disabledReason());
			$this->assertSame(array('HTTP_X_FORWARDED_FOR'), $state->updateHeaders());
			$this->assertFalse($state->isCompleted());
			$this->assertTrue($state->fromBefore200());

			// once the setup is complete, an update leaves the plugin as it is
			$this->db->setQuery("UPDATE #__extensions SET enabled=1 WHERE type='plugin' AND folder='system' AND element='bfstop'")->execute();
			\PlgsystembfstopInstallerScript::writeSetupState($this->db, array('completed' => time()));
			$this->update('2.0.0', array('blockMode' => 'full'));
			$this->assertSame(1, (int) $this->queryValue($enabled));
		}
		finally
		{
			$_SERVER = $server;
			$this->setSettings($original);
			$this->setPluginParams($pluginParams);
			$this->db->setQuery("UPDATE #__extensions SET enabled=".$before." WHERE type='plugin' AND folder='system' AND element='bfstop'")->execute();
			Factory::getApplication()->getMessageQueue(true);
		}
	}

	/** On the command line, there is no request: Joomla's "Behind Load Balancer" decides. */
	public function testTheReasonToDisableThePluginDuringAnUpdate()
	{
		$direct = array('REMOTE_ADDR' => '203.0.113.5');
		$proxied = array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7');
		$this->assertNull(\PlgsystembfstopInstallerScript::setupDisableReason($direct, false, false));
		$this->assertNull(\PlgsystembfstopInstallerScript::setupDisableReason($direct, false, true), 'not a signal in the browser');
		$this->assertSame('proxy', \PlgsystembfstopInstallerScript::setupDisableReason($proxied, false, false));
		$this->assertNull(\PlgsystembfstopInstallerScript::setupDisableReason($proxied, true, false), 'the console has no request');
		$this->assertSame('loadbalancer', \PlgsystembfstopInstallerScript::setupDisableReason($direct, true, true));
		$this->assertSame('proxy', \PlgsystembfstopInstallerScript::setupDisableReason(
			array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.7'), false, false), 'E: only X-Real-IP');
		$this->assertNull(\PlgsystembfstopInstallerScript::setupDisableReason(
			array('REMOTE_ADDR' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'), false, false), 'C: the server resolves it');
	}

	/**
	 * The update tells the scenarios apart without the library (see
	 * proxyScenario()): the same way as the library's ProxyDetector, with the
	 * same headers and networks.
	 */
	public function testTheUpdateDetectsTheScenarioAsTheLibraryDoes()
	{
		$this->assertSame(\Codeling\Library\Bfstop\Helper\IpHelper::KnownProxyHeaders, \PlgsystembfstopInstallerScript::SupportedProxyHeaders);
		$this->assertSame(array_keys(\Codeling\Library\Bfstop\Helper\IpHelper::UnsupportedProxyHeaders),
			\PlgsystembfstopInstallerScript::UnsupportedProxyHeaders);
		$this->assertSame(\Codeling\Library\Bfstop\Helper\IpHelper::NonPublicNetworks, \PlgsystembfstopInstallerScript::NonPublicNetworks);
		$proxy = array('useProxy' => false, 'header' => 'HTTP_X_FORWARDED_FOR', 'trusted' => array());
		foreach (\Codeling\Bfstop\Tests\Unit\ProxyDetectorTest::scenarios() as $name => list($server, $expected))
		{
			$this->assertSame($expected, \PlgsystembfstopInstallerScript::proxyScenario($server), $name);
			$this->assertSame($expected, \Codeling\Library\Bfstop\Service\Setup\ProxyDetector::detect($server, $proxy, false)['scenario'], $name);
		}
	}

	/**
	 * Runs the update of the installed plugin from $fromVersion, whose stored
	 * settings are $params - in the plugin's params before 2.0.0, in the
	 * component's since; returns the settings afterwards, which are the
	 * component's.
	 */
	private function update($fromVersion, array $params)
	{
		$this->setInstalledVersion($fromVersion);
		$before200 = version_compare($fromVersion, '2.0.0-dev', '<');
		$this->setSettings($before200 ? '{}' : json_encode($params));
		$this->setPluginParams($before200 ? json_encode($params) : '{}');
		list($script, $adapter) = $this->script();
		$this->assertTrue($script->preflight('update', $adapter));
		$script->update($adapter);
		$script->postflight('update', $adapter);
		$this->assertSame(array(), json_decode($this->pluginParams(), true), 'no settings are left with the plugin');
		return json_decode($this->getSettings(), true);
	}

	/**
	 * Until 2.0.0, the settings were the plugin's params; the update moves
	 * them to the component, whose params they are now (see the library's
	 * Settings) - once: a later update finds them there.
	 */
	public function testUpdateFromBefore200MovesTheSettingsToTheComponent()
	{
		$original = $this->getSettings();
		try
		{
			$params = $this->update('1.5.2', array('blockMode' => 'htaccess', 'blockNumber' => '7',
				'emailaddress' => "a@example.org\nb@example.org", 'settingsMoved' => ''));
			$this->assertSame('htaccess', $params['blockMode']);
			$this->assertSame('7', $params['blockNumber']);
			$this->assertSame("a@example.org\nb@example.org", $params['emailaddress']);
			$this->assertArrayNotHasKey('settingsMoved', $params, 'the note of the plugin\'s form is no setting');
			$this->forgetLoadedSettings();
			$this->assertSame('7', \Codeling\Library\Bfstop\Settings::stored()->get('blockNumber'));

			// what the component's "Options" page of 1.x stored stays, the
			// settings come to it
			$this->setSettings(json_encode(array('somethingElse' => 1)));
			$this->setInstalledVersion('1.5.2');
			$this->setPluginParams(json_encode(array('blockMode' => 'off')));
			list($script, $adapter) = $this->script();
			$this->assertTrue($script->preflight('update', $adapter));
			$script->update($adapter);
			$this->assertSame(array('somethingElse' => 1, 'blockMode' => 'off'), json_decode($this->getSettings(), true));

			// a later update leaves them where they are
			$params = $this->update('2.0.0', array('blockMode' => 'full', 'blockNumber' => '9'));
			$this->assertSame('9', $params['blockNumber']);
		}
		finally
		{
			$this->setSettings($original);
		}
	}

	public function testAnUpdateWhichCannotMigrateTellsTheAdministrator()
	{
		// it used to swallow the exception without a trace
		Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
		$original = $this->getSettings();
		$table = $this->db->quoteName('#__bfstop_state');
		$away = $this->db->quoteName('#__bfstop_state_away');
		$this->db->setQuery('ALTER TABLE '.$table.' RENAME TO '.$away)->execute();
		try
		{
			$this->setInstalledVersion('2.0.0');
			list($script, $adapter) = $this->script();
			$this->assertTrue($script->preflight('update', $adapter));
			$this->assertTrue($script->update($adapter), 'the update itself goes on');
			$script->postflight('update', $adapter);
			$failed = strip_tags(\Joomla\CMS\Language\Text::sprintf('PLG_SYSTEM_BFSTOP_UPDATE_MIGRATION_FAILED', '', ''));
			$shown = array_filter($this->messages(), fn ($message) =>
				str_starts_with(strip_tags($message), substr($failed, 0, 40)));
			$this->assertCount(1, $shown, 'the administrator is told');
		}
		finally
		{
			$this->db->setQuery('ALTER TABLE '.$away.' RENAME TO '.$table)->execute();
			$this->setSettings($original);
		}
	}

	public function testUpdateFromBefore200ProtectsTheApi()
	{
		$original = $this->getSettings();
		try
		{
			// the frontend/backend setting of 1.x knew nothing of the API;
			// the setup assistant's overview says that it is protected now
			$params = $this->update('1.5.2', array('blockEnabled' => '1', 'enabledForOrigin' => '2'));
			$this->assertSame(6, $params['enabledForOrigin'], 'backend only became backend and API');
			$this->assertSame('full', $params['blockMode']);
			// never saved: its default protects the API anyway
			$params = $this->update('1.5.2', array('blockEnabled' => '1'));
			$this->assertArrayNotHasKey('enabledForOrigin', $params);
			// a later update leaves the choice alone
			$params = $this->update('2.0.0', array('blockMode' => 'full', 'enabledForOrigin' => 3));
			$this->assertSame(3, $params['enabledForOrigin']);
		}
		finally
		{
			$this->setSettings($original);
		}
	}

	public function testTheUpdateRemovesTheDelaysAndTellsWhoUsedThem()
	{
		// 2.0.0 delays no response (a held response holds a PHP worker)
		Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
		$notice = strip_tags(\Joomla\CMS\Language\Text::_('PLG_SYSTEM_BFSTOP_UPDATE_2_0_0_DELAYS_REMOVED'));
		$noticeShown = function () use ($notice)
		{
			return in_array($notice, array_map('strip_tags', $this->messages()), true);
		};
		$original = $this->getSettings();
		try
		{
			$params = $this->update('1.5.2', array('blockEnabled' => '1', 'blockNumber' => '7', 'delayDuration' => '20',
				'adaptiveDelay' => '0', 'adaptiveDelayMax' => '60', 'adaptiveDelayThresholdMin' => '50',
				'adaptiveDelayThresholdMax' => '200'));
			foreach (\PlgsystembfstopInstallerScript::RemovedDelaySettings as $name)
			{
				$this->assertArrayNotHasKey($name, $params, $name);
			}
			$this->assertSame('7', $params['blockNumber'], 'the other settings stay');
			$this->assertTrue($noticeShown(), 'responses were delayed');

			// the adaptive delay alone delayed them as well
			$this->update('1.5.2', array('blockEnabled' => '1', 'delayDuration' => '0', 'adaptiveDelay' => '1',
				'adaptiveDelayMax' => '30'));
			$this->assertTrue($noticeShown());

			// saved, but delaying nothing: removed without a notice
			$params = $this->update('1.5.2', array('blockEnabled' => '1', 'delayDuration' => '0', 'adaptiveDelay' => '0'));
			$this->assertArrayNotHasKey('delayDuration', $params);
			$this->assertFalse($noticeShown());
			$this->update('2.0.0', array('blockMode' => 'full'));
			$this->assertFalse($noticeShown());
		}
		finally
		{
			$this->setSettings($original);
		}
	}

	public function testRemovingTheDelaySettings()
	{
		$params = array('delayDuration' => '5', 'blockNumber' => '3');
		$this->assertSame(array('delayed' => true), \PlgsystembfstopInstallerScript::removeDelaySettings($params));
		$this->assertSame(array('blockNumber' => '3'), $params);
		$this->assertNull(\PlgsystembfstopInstallerScript::removeDelaySettings($params), 'none left');
		$params = array('adaptiveDelay' => '1', 'adaptiveDelayMax' => '0');
		$this->assertSame(array('delayed' => false), \PlgsystembfstopInstallerScript::removeDelaySettings($params),
			'adaptive, but up to 0 seconds');
	}

	public function testStoredAddressesAreConvertedByTheUpdateFromBefore200()
	{
		// entries of earlier versions, or typed by hand, are not in the canonical form
		// the lookups of the block and allow list rely on; until 2.0.0, the first
		// request after the update converted them, and now the update does
		$original = $this->getSettings();
		try
		{
			$upper = $this->insert('#__bfstop_bannedip', array('ipaddress' => '2001:DB8::41', 'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
			$allow = $this->insert('#__bfstop_allowlist', array('ipaddress' => '10.1.2.3/16', 'notes' => ''), 'id');
			$this->update('1.5.2', array('blockEnabled' => '1'));
			$this->assertSame('2001:db8::41', $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip WHERE id='.$upper));
			$this->assertSame('10.1.0.0/16', $this->queryValue('SELECT ipaddress FROM #__bfstop_allowlist WHERE id='.$allow));
			$this->assertTrue((new Repositories($this->logger))->blocks()->isBlocked('2001:db8::41'));
			// a later update has nothing to convert (and doesn't read the lists)
			$this->db->setQuery("UPDATE #__bfstop_bannedip SET ipaddress='2001:DB8::41' WHERE id=".$upper)->execute();
			$this->update('2.0.0', array('blockMode' => 'full'));
			$this->assertSame('2001:DB8::41', $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip WHERE id='.$upper));
		}
		finally
		{
			$this->setSettings($original);
		}
	}

	public function testTheInstallersSpellingOfAddressesIsThatOfTheLookups()
	{
		// the update can't call IpHelper (the class of the version it replaces may be
		// loaded), so it has a copy of the canonical form: they must agree
		$samples = array('203.0.113.5', '203.0.113.77/24', '203.0.113.0/24', '10.0.0.1/8', '0.0.0.0/0', '1.2.3.4/32',
			'2001:DB8::ABCD', '2001:0DB8:0:0:0:0:0:5/64', '2001:db8:1:2::/64', '::1', '::/0', '2001:db8::1/128',
			'2001:db8::1/127', '::ffff:203.0.113.5', '::FFFF:CB00:7105', '::ffff:203.0.113.77/120', '::ffff:1.2.3.4/80',
			'::ffff:1.2.3.4/abc', ' 203.0.113.5 ', '203.0.113.5/33', '2001:db8::/129',
			'203.0.113.0/abc', '203.0.113.5/', 'nonsense', '', '1.2.3', '203.0.113.5/24/8', '203.0.113.5/-1');
		foreach ($samples as $sample)
		{
			$this->assertSame(IpHelper::canonicalEntry($sample), \PlgsystembfstopInstallerScript::canonicalAddress($sample),
				"'$sample'");
		}
	}

	public function testTheInstallerTellsThePluginsBlocksAsTheHelperDoes()
	{
		// a copy too, for the uninstallation: what is the plugin's block, what
		// was written by hand
		$page = " && !(%{REQUEST_URI} == '/index.php' && %{QUERY_STRING} =~ /".HtaccessHelper::UnblockQueryPattern."/)";
		$samples = array(
			"<If \"-R '192.0.2.1'\">", "<If \"-R '192.0.2.1' || -R '2001:db8::/56'\">",
			"<If \"(-R '192.0.2.1')".$page."\">", "<If \"(-R '192.0.2.1' || -R '192.0.2.2')".$page."\">",
			"<If \"%{HTTP_HOST} == 'x'\">", "<If \"-R '192.0.2.1' && %{REQUEST_URI} =~ m#^/a#\">",
			"<If \"-R '192.0.2.1' || %{HTTP_HOST} == 'x'\">", "<IfModule mod_headers.c>", "Require all denied", '');
		$helper = new \ReflectionMethod(HtaccessHelper::class, 'blockConditionAddresses');
		$installer = new \ReflectionMethod(\PlgsystembfstopInstallerScript::class, 'isBlockCondition');
		foreach ($samples as $sample)
		{
			$this->assertSame($helper->invoke(null, $sample) !== null, $installer->invoke(null, $sample), $sample);
		}
		$this->assertSame(array('192.0.2.1', '192.0.2.2'), $helper->invoke(null, $samples[3]));
	}

	public function testStoredAddressesAreConvertedInBatches()
	{
		// more entries than one batch of the conversion
		$values = array();
		for ($i = 0; $i < 5100; ++$i)
		{
			$values[] = "('10.".intdiv($i, 250).'.'.($i % 250).".1/16', '".self::minutesAgo(0)."', 60)";
		}
		$this->db->setQuery('INSERT INTO #__bfstop_bannedip (ipaddress, crdate, duration) VALUES '.implode(',', $values));
		$this->db->execute();
		$this->insert('#__bfstop_bannedip', array('ipaddress' => '203.0.113.0/abc', 'crdate' => self::minutesAgo(0), 'duration' => 60));
		$this->assertSame(5100, \PlgsystembfstopInstallerScript::canonicalizeAddresses($this->db));
		$this->assertSame(0, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_bannedip WHERE ipaddress LIKE '%.1/16'"));
		$this->assertSame(1, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_bannedip WHERE ipaddress = '203.0.113.0/abc'"),
			'what is no entry is left alone');
		$this->assertSame(0, \PlgsystembfstopInstallerScript::canonicalizeAddresses($this->db), 'nothing left to do');
	}

	public function testBookkeepingMovesOutOfTheSettingsIntoTheStateTable()
	{
		// a request which saved when it ran the maintenance wrote all the settings back
		// as it had read them, racing with an administrator saving the settings page
		$original = $this->getSettings();
		try
		{
			$params = $this->update('1.5.2', array('blockMode' => 'full', 'lastPurge' => 1700000000, 'addressesCanonical' => 1));
			$this->assertArrayNotHasKey('lastPurge', $params);
			$this->assertArrayNotHasKey('addressesCanonical', $params);
			$this->assertSame('full', $params['blockMode'], 'the settings stay');
			$this->assertSame('1700000000', $this->queryValue("SELECT value FROM #__bfstop_state WHERE name='lastMaintenance'"),
				'the maintenance ran then');
			// updating again doesn't make it newer
			$this->update('2.0.0', array('blockMode' => 'full', 'lastPurge' => 1800000000));
			$this->assertSame('1700000000', $this->queryValue("SELECT value FROM #__bfstop_state WHERE name='lastMaintenance'"));
			// never run, as far as it says: it is due - the task is the first to do it
			$this->db->setQuery('DELETE FROM #__bfstop_state')->execute();
			$this->update('2.0.0', array('blockMode' => 'full'));
			$this->assertGreaterThan(time() - 60, (int) $this->queryValue("SELECT value FROM #__bfstop_state WHERE name='lastMaintenance'"));
		}
		finally
		{
			$this->setSettings($original);
		}
	}

	public function testInstallationSeedsTheMaintenanceState()
	{
		// the task is made by the task plugin, which the package installs next: a
		// request needn't do the maintenance of a site which has nothing to purge
		list($script, $adapter) = $this->script();
		$this->assertTrue($script->install($adapter));
		$this->assertGreaterThan(time() - 60, (int) $this->queryValue("SELECT value FROM #__bfstop_state WHERE name='lastMaintenance'"));
	}

	public function testTaskPluginInstallationMakesTheScheduledTaskOnce()
	{
		$script = require_once dirname(__DIR__, 2).'/task/script.php';
		$taskRows = function ()
		{
			return (int) $this->queryValue("SELECT COUNT(*) FROM #__scheduler_tasks WHERE type='bfstop.maintenance'");
		};
		$this->db->setQuery("DELETE FROM #__scheduler_tasks WHERE type='bfstop.maintenance'")->execute();
		try
		{
			$adapter = $this->createMock(InstallerAdapter::class);
			$this->assertTrue($script->install($adapter));
			$this->assertSame(1, $taskRows());
			$task = $this->db->setQuery("SELECT * FROM #__scheduler_tasks WHERE type='bfstop.maintenance'")->loadObject();
			$this->assertSame(1, (int) $task->state);
			$this->assertSame('PT24H', json_decode($task->cron_rules)->exp, 'every 24 hours');
			$this->assertLessThanOrEqual(time(), strtotime($task->next_execution.' UTC'), 'due');
			$this->assertSame(1, (int) $this->queryValue("SELECT enabled FROM #__extensions WHERE type='plugin' AND folder='task' AND element='bfstop'"),
				'the plugin which runs it is switched on');
			// installing again (the update from a version which made it) adds none
			$this->assertTrue($script->install($adapter));
			$this->assertSame(1, $taskRows());
			// uninstalling takes it away
			$this->assertTrue($script->uninstall($adapter));
			$this->assertSame(0, $taskRows());
		}
		finally
		{
			// the site as it was installed: with its task
			\PlgtaskbfstopInstallerScript::createTask($this->db);
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
		$original = $this->getSettings();
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
			$this->setSettings($original);
		}
	}

	public function testUninstallRemovesTheBlockSection()
	{
		// nothing would ever take the addresses out of it again: the web
		// server would refuse them for good
		Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
		$dir = sys_get_temp_dir().'/bfstop-uninstall-htaccess-'.bin2hex(random_bytes(4));
		mkdir($dir);
		$original = $this->getSettings();
		$section = "# BEGIN BFStop Blocks\n<If \"-R '192.0.2.1' || -R '2001:db8::/56'\">\nRequire all denied\n</If>\n".
			"ErrorDocument 403 \"Go away\"\n";
		$notRemoved = strip_tags(\Joomla\CMS\Language\Text::sprintf('PLG_SYSTEM_BFSTOP_UNINSTALL_HTACCESS_NOT_REMOVED', $dir.'/.htaccess'));
		$uninstall = function ()
		{
			list($script, $adapter) = $this->script();
			$script->uninstall($adapter);
		};
		try
		{
			$this->setSettings(json_encode(array('blockMode' => 'full', 'htaccessPath' => $dir)));
			file_put_contents($dir.'/.htaccess', $section."# END BFStop Blocks\n\nAuthType Basic\nRequire valid-user\n");
			$uninstall();
			$this->assertSame("AuthType Basic\nRequire valid-user\n", file_get_contents($dir.'/.htaccess'));

			// what somebody else wrote into the section stays
			file_put_contents($dir.'/.htaccess', "Options -Indexes\n".$section."Header set X-Test 1\n# END BFStop Blocks\n");
			$uninstall();
			$this->assertSame("Options -Indexes\n# BEGIN BFStop Blocks\nHeader set X-Test 1\n# END BFStop Blocks\n",
				file_get_contents($dir.'/.htaccess'));
			$this->assertNotContains($notRemoved, array_map('strip_tags', $this->messages()));

			// and so does an <If> somebody wrote into it, all of it - and the
			// plugin's blocks of the current form go
			$hand = "<If \"%{HTTP_HOST} == 'old.example.org'\">\nRequire all denied\n</If>\n";
			$current = "<If \"(-R '192.0.2.1') && !(%{REQUEST_URI} == '/index.php' && %{QUERY_STRING} =~ /".
				\Codeling\Library\Bfstop\Helper\HtaccessHelper::UnblockQueryPattern."/)\">\nRequire all denied\n</If>\n";
			file_put_contents($dir.'/.htaccess', "# BEGIN BFStop Blocks\n".$current.$hand."# END BFStop Blocks\n");
			$uninstall();
			$this->assertSame("# BEGIN BFStop Blocks\n".$hand."# END BFStop Blocks\n", file_get_contents($dir.'/.htaccess'));

			// no file, no section: nothing to do
			$this->assertTrue(\PlgsystembfstopInstallerScript::removeHtaccessSection($dir.'/none/.htaccess'));
			file_put_contents($dir.'/.htaccess', "AuthType Basic\n");
			$this->assertTrue(\PlgsystembfstopInstallerScript::removeHtaccessSection($dir.'/.htaccess'));
			$this->assertSame("AuthType Basic\n", file_get_contents($dir.'/.htaccess'));

			if (!function_exists('posix_geteuid') || posix_geteuid() !== 0)
			{
				file_put_contents($dir.'/.htaccess', $section."# END BFStop Blocks\n");
				chmod($dir.'/.htaccess', 0444);
				chmod($dir, 0555);
				$uninstall();
				$this->assertContains($notRemoved, array_map('strip_tags', $this->messages()));
			}
		}
		finally
		{
			@chmod($dir, 0755);
			@chmod($dir.'/.htaccess', 0644);
			@unlink($dir.'/.htaccess');
			@rmdir($dir);
			$this->setSettings($original);
		}
	}

	/**
	 * The classes which the library has since 2.0.0 are taken out of the
	 * plugin's directory by the update; the plugin's own stay.
	 */
	public function testUpdateRemovesTheClassesWhichAreTheLibrarys()
	{
		$root = sys_get_temp_dir().'/bfstop-moved-'.bin2hex(random_bytes(4));
		foreach (array('src/Helper/Geo/Reader.php', 'src/Helper/IpHelper.php', 'src/Repository/Repository.php',
			'src/Service/BlockPolicy.php', 'src/Service/MaintenanceSchedule.php', 'src/Service/Responder.php',
			'src/Extension/Bfstop.php') as $file)
		{
			@mkdir(dirname($root.'/'.$file), 0777, true);
			file_put_contents($root.'/'.$file, '<?php');
		}
		try
		{
			\PlgsystembfstopInstallerScript::removeMovedToLibrary($root);
			$this->assertDirectoryDoesNotExist($root.'/src/Helper');
			$this->assertDirectoryDoesNotExist($root.'/src/Repository');
			$this->assertFileDoesNotExist($root.'/src/Service/BlockPolicy.php');
			$this->assertFileDoesNotExist($root.'/src/Service/MaintenanceSchedule.php');
			$this->assertFileExists($root.'/src/Service/Responder.php');
			$this->assertFileExists($root.'/src/Extension/Bfstop.php');
			// and once more, with nothing left to remove
			\PlgsystembfstopInstallerScript::removeMovedToLibrary($root);
			$this->assertFileExists($root.'/src/Extension/Bfstop.php');
		}
		finally
		{
			exec('rm -rf '.escapeshellarg($root));
		}
	}
}
