<?php
/*
 * @package BFStop for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Component\Bfstop\Administrator\Controller\DisplayController;
use Codeling\Component\Bfstop\Administrator\Model\SetupModel;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\Setup\ProxyDetector;
use Codeling\Library\Bfstop\Service\Setup\SetupState;
use Codeling\Plugin\Quickicon\Bfstop\Extension\Bfstop as QuickIcon;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Factory\MVCFactory;
use Joomla\Module\Quickicon\Administrator\Event\QuickIconsEvent;

/**
 * The setup assistant (the component's SetupModel and its banners, the
 * quick icon, the console commands): its steps saved through the settings
 * model, the dry run of the proxy settings, the values which keep the
 * settings from being saved, and the activation of protection.
 */
class SetupTest extends IntegrationTestCase
{
	private const Enabled = "SELECT enabled FROM #__extensions WHERE type='plugin' AND folder='system' AND element='bfstop'";

	private $originalSettings;
	private $originalEnabled;
	private $originalServer;
	private $originalIdentity;

	protected function setUp(): void
	{
		parent::setUp();
		$this->originalSettings = $this->getSettings();
		$this->originalEnabled = (int) $this->queryValue(self::Enabled);
		$this->originalServer = $_SERVER;
		$app = Factory::getApplication();
		$this->originalIdentity = $app->getIdentity();
		$app->getLanguage()->load('com_bfstop', BFSTOP_COMPONENT_ROOT.'/admin', null, true);
		$app->getLanguage()->load('plg_system_bfstop.sys', BFSTOP_PLUGIN_ROOT, null, true);
		$app->getLanguage()->load('plg_quickicon_bfstop', dirname(__DIR__, 2).'/quickicon', null, true);
		$app->loadIdentity($this->adminUser());
		$app->getMessageQueue(true);
	}

	protected function tearDown(): void
	{
		$_SERVER = $this->originalServer;
		self::storeSettings($this->db, $this->originalSettings);
		$this->setPluginEnabled($this->originalEnabled);
		Factory::getApplication()->loadIdentity($this->originalIdentity);
		Factory::getApplication()->getMessageQueue(true);
	}

	/** The site's super user. */
	private function adminUser()
	{
		$id = (int) $this->queryValue("SELECT u.id FROM #__users u INNER JOIN #__user_usergroup_map m ON m.user_id = u.id ".
			"WHERE m.group_id = 8 ORDER BY u.id");
		return Factory::getContainer()->get(\Joomla\CMS\User\UserFactoryInterface::class)->loadUserById($id);
	}

	private function setPluginEnabled($enabled)
	{
		$this->db->setQuery('UPDATE #__extensions SET enabled='.(int) $enabled.
			" WHERE type='plugin' AND folder='system' AND element='bfstop'")->execute();
	}

	private function model(): SetupModel
	{
		$model = new SetupModel(array('dbo' => $this->db), new MVCFactory('Codeling\\Component\\Bfstop'));
		$model->setDatabase($this->db);
		return $model;
	}

	private function stored()
	{
		return json_decode((string) $this->getSettings(), true) ?: array();
	}

	private static function errors(SetupModel $model)
	{
		return implode(' ', array_map(fn ($e) => $e instanceof \Throwable ? $e->getMessage() : (string) $e, $model->getErrors()));
	}

	private function state(): SetupState
	{
		return SetupState::load((new Repositories($this->logger))->state());
	}

	/**
	 * Settings as 1.5.2 left them (moved to the component by the update):
	 * each value which the settings page refuses now is found, with a fix,
	 * by the settings form's own validation; the fixes are saved with the
	 * first step, and nothing blocks saving afterwards.
	 */
	public function testStoredValuesWhichBlockSavingAreFixedWithTheStep()
	{
		$_SERVER['SERVER_SOFTWARE'] = 'nginx/1.25.4';
		$_SERVER['REMOTE_ADDR'] = '203.0.113.5';
		self::storeSettings($this->db, json_encode(array(
			'blockEnabled' => '1', 'useHtaccess' => '1', 'blockMode' => 'htaccess',
			'emailaddress' => 'admin@example.org;', 'htaccessPath' => '/no/such/directory/bfstop',
			'notifyBlockedUser' => '1', 'blockNumber' => '5', 'riskMinBlockNumber' => '9', 'blockDuration' => '7',
		)));
		Factory::getApplication()->set('live_site', '');
		$model = $this->model();
		$blocking = $model->blockingValues();
		$this->assertEqualsCanonicalizing(array('emailaddress', 'htaccessPath', 'blockMode', 'notifyBlockedUser',
			'riskMinBlockNumber', 'blockDuration'), array_keys($blocking));
		$this->assertSame('admin@example.org', $blocking['emailaddress']['fix']);
		$this->assertSame('full', $blocking['blockMode']['fix']);
		$this->assertSame('0', $blocking['notifyBlockedUser']['fix']);
		$this->assertSame('5', $blocking['riskMinBlockNumber']['fix']);
		$this->assertSame('1440', $blocking['blockDuration']['fix']);
		foreach ($blocking as $field => $entry)
		{
			$this->assertNotSame('', $entry['message'], $field);
			$this->assertStringNotContainsString('COM_BFSTOP_', $entry['label'].$entry['message'], $field);
		}
		$this->assertContains('blockingValues', $model->missingForActivation($_SERVER));
		$this->assertContains('modeUnfit', $model->missingForActivation($_SERVER));

		// the administrator changes one proposal
		$this->assertTrue($model->confirmNoProxy(false, array('emailaddress' => 'security@example.org'), $_SERVER), self::errors($model));
		$stored = $this->stored();
		$this->assertSame('security@example.org', $stored['emailaddress']);
		$this->assertSame('full', $stored['blockMode']);
		$this->assertSame('0', (string) $stored['useProxy']);
		$this->assertArrayNotHasKey('useHtaccess', $stored, 'what is no setting any more is dropped, as by the settings page');
		self::forgetLoadedSettings();
		$this->assertSame(array(), $this->model()->blockingValues());
		$this->assertSame(SetupState::Done, $this->state()->status(SetupState::StepProxy));
	}

	/**
	 * Behind a proxy, the settings are only saved after the dry run showed
	 * the administrator's own address and they confirmed it; "no proxy"
	 * needs their word that the site is reached directly all the same, and
	 * isn't possible at all where only headers BFStop can't read arrive.
	 */
	public function testTheProxyStepChecksTheSettingsWithTheRequest()
	{
		$server = array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1, 203.0.113.7');
		$model = $this->model();
		$this->assertSame('B', $model->detection($server)['scenario']);
		$this->assertFalse($model->confirmNoProxy(false, array(), $server), 'B: no proxy without acknowledging it');
		$this->assertFalse($model->confirmProxy('HTTP_X_FORWARDED_FOR', '10.0.0.5', null, array(), $server), 'not confirmed');
		$this->assertFalse($model->confirmProxy('HTTP_X_FORWARDED_FOR', '10.0.0.6', '10.0.0.5', array(), $server), 'not trusted');
		$this->assertFalse($model->confirmProxy('HTTP_FORWARDED', '10.0.0.5', '203.0.113.7', array(), $server), 'no such header');
		$this->assertFalse($model->confirmProxy('HTTP_X_FORWARDED_FOR', '10.0.0.5', '198.51.100.1', array(), $server),
			'the address confirmed is not the one these settings give');
		$this->assertFalse($model->confirmProxy('HTTP_X_REAL_IP', '10.0.0.5', '203.0.113.7', array(), $server), 'a header BFStop doesn\'t read');
		$this->assertSame(SetupState::Pending, $this->state()->status(SetupState::StepProxy));

		$this->assertTrue($model->confirmProxy('HTTP_X_FORWARDED_FOR', '10.0.0.5', '203.0.113.7', array(), $server), self::errors($model));
		$stored = $this->stored();
		$this->assertSame('1', (string) $stored['useProxy']);
		$this->assertSame('10.0.0.5', $stored['proxyIpAddress']);
		$this->assertSame('HTTP_X_FORWARDED_FOR', $stored['proxyHeaderSource']);
		$state = $this->state();
		$this->assertSame(SetupState::Done, $state->status(SetupState::StepProxy));
		$this->assertSame(ProxyDetector::fingerprint('B', 'HTTP_X_FORWARDED_FOR', true), $state->confirmedFingerprint());

		// acknowledged: there is a header, but no proxy in front of the site
		$this->assertTrue($this->model()->confirmNoProxy(true, array(), $server), 'acknowledged');
		$this->assertSame('0', (string) $this->stored()['useProxy']);

		$unsupported = array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.7');
		$model = $this->model();
		$this->assertFalse($model->confirmNoProxy(true, array(), $unsupported), 'E: there is a proxy');
		$this->assertSame(\Joomla\CMS\Language\Text::_('COM_BFSTOP_SETUP_PROXY_ERROR_UNSUPPORTED'), self::errors($model));
	}

	/** The blocking-mode step: "Reporting Only" only when confirmed, flagged after an update which removed delays. */
	public function testTheBlockingModeStep()
	{
		$_SERVER['SERVER_SOFTWARE'] = 'nginx/1.25.4';
		self::storeSettings($this->db, json_encode(array('blockMode' => 'off')));
		(new Repositories($this->logger))->state()->set(SetupState::Name, json_encode(array('mode' => 'upgrade',
			'from' => '1.5.2', 'delays' => 1)));
		$model = $this->model();
		$advice = $model->blockModeAdvice($_SERVER);
		$this->assertSame('nginx', $advice['server']);
		$this->assertContains('nginx', $advice['warnings']);
		$this->assertContains('unprotected', $advice['warnings'], 'Reporting Only with the delays of 1.5.2: unprotected now');
		$this->assertSame('full', $advice['recommended']);

		$this->assertFalse($model->confirmBlockMode('off', null, false));
		$this->assertFalse($model->confirmBlockMode('htaccess', null, false), 'nginx never reads .htaccess');
		$this->assertFalse($model->confirmBlockMode('nonsense', null, false));
		$this->assertSame(SetupState::Pending, $this->state()->status(SetupState::StepBlockMode));
		$this->assertTrue($model->confirmBlockMode('full', '', false), self::errors($model));
		$this->assertSame('full', $this->stored()['blockMode']);
		$this->assertSame(SetupState::Done, $this->state()->status(SetupState::StepBlockMode));
		$this->assertTrue($this->model()->confirmBlockMode('off', null, true), 'confirmed');

		$_SERVER['SERVER_SOFTWARE'] = 'Apache/2.4.58';
		self::storeSettings($this->db, json_encode(array('blockMode' => 'htaccess', 'useProxy' => '1', 'proxyIpAddress' => '10.0.0.5')));
		$this->assertContains('htaccessProxy', $this->model()->blockModeAdvice($_SERVER)['warnings']);
		self::storeSettings($this->db, json_encode(array('blockMode' => 'off')));
		(new Repositories($this->logger))->state()->set(SetupState::Name, json_encode(array('mode' => 'install')));
		$this->assertContains('reportingOnly', $this->model()->blockModeAdvice($_SERVER)['warnings']);
	}

	/**
	 * "Activate protection" enables the plugin once the required steps are
	 * done, and records it; the User Actions Log has the steps and the
	 * activation.
	 */
	public function testActivationNeedsTheRequiredSteps()
	{
		$this->setPluginEnabled(0);
		$server = array('REMOTE_ADDR' => '203.0.113.5');
		$model = $this->model();
		$this->assertSame(array(SetupState::StepProxy, SetupState::StepBlockMode), $model->missingForActivation($server));
		$this->assertFalse($model->activate($server));
		$this->assertSame(0, (int) $this->queryValue(self::Enabled));

		$this->assertTrue($model->confirmNoProxy(false, array(), $server), self::errors($model));
		$this->assertTrue($model->confirmBlockMode('full', null, false), self::errors($model));
		$this->assertSame(array(), $model->missingForActivation($server));
		$this->assertTrue($model->activate($server), self::errors($model));
		$this->assertSame(1, (int) $this->queryValue(self::Enabled));
		$this->assertTrue($model->pluginEnabled());
		$this->assertTrue($this->state()->isCompleted());
		$this->assertGreaterThan(0, (int) $this->queryValue("SELECT COUNT(*) FROM #__action_logs WHERE ".
			"message_language_key='COM_BFSTOP_ACTIONLOG_PROTECTION_ACTIVATED'"));
		$this->assertGreaterThan(0, (int) $this->queryValue("SELECT COUNT(*) FROM #__action_logs WHERE ".
			"message_language_key='COM_BFSTOP_ACTIONLOG_SETUP_STEP_APPLIED'"));
	}

	/** The banners of the BFStop backend, for who may change the settings only. */
	public function testBannersOfTheBackend()
	{
		$_SERVER['REMOTE_ADDR'] = '10.0.0.5';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.7';
		self::storeSettings($this->db, json_encode(array('useProxy' => '0')));
		$app = Factory::getApplication();
		$messages = function ($pluginEnabled) use ($app)
		{
			$controller = new DisplayController(array('base_path' => JPATH_ADMINISTRATOR.'/components/com_bfstop'),
				new MVCFactory('Codeling\\Component\\Bfstop'), $app, $app->getInput());
			$controller->showSetupBanners($pluginEnabled);
			return array_map(fn ($m) => $m['type'].': '.strip_tags($m['message']), $app->getMessageQueue(true));
		};
		$notActive = 'error: '.strip_tags(\Joomla\CMS\Language\Text::sprintf('COM_BFSTOP_BANNER_NOT_ACTIVE', ''));
		$incomplete = 'warning: '.strip_tags(\Joomla\CMS\Language\Text::sprintf('COM_BFSTOP_BANNER_SETUP_INCOMPLETE', ''));
		$proxy = strip_tags(\Joomla\CMS\Language\Text::_('COM_BFSTOP_SETUP_MISMATCH_APPEARSBEHINDPROXY'));
		$shown = $messages(false);
		$this->assertContains($notActive, $shown);
		$this->assertCount(1, array_filter($shown, fn ($m) => str_contains($m, $proxy)));
		$this->assertContains($incomplete, $messages(true));

		// dismissed: not shown again; the setup completed: no banner of it
		$mismatch = $this->model()->mismatches()[0];
		$this->model()->dismiss($mismatch['fingerprint']);
		(new Repositories($this->logger))->state()->set(SetupState::Name, json_encode(array('completed' => time())));
		$this->assertSame(array(), $messages(true));

		// who may only look at the lists can't do anything about it
		$this->db->setQuery("DELETE FROM #__bfstop_state")->execute();
		$app->loadIdentity(new \Joomla\CMS\User\User());
		$this->assertSame(array(), $messages(false));
	}

	/**
	 * The quick icon of the Home Dashboard: in the notification area (the
	 * context of Joomla's own status tiles), its three states, and the plain
	 * tile for who may not change the settings.
	 */
	public function testTheQuickIcon()
	{
		$manifest = simplexml_load_file(dirname(__DIR__, 2).'/quickicon/bfstop.xml');
		$this->assertSame('update_quickicon', (string) $manifest->xpath('//field[@name="context"]/@default')[0]);
		$this->assertSame(QuickIcon::Inactive, QuickIcon::state(false, true, false));
		$this->assertSame(QuickIcon::Incomplete, QuickIcon::state(true, false, true));
		$this->assertSame(QuickIcon::Mismatch, QuickIcon::state(true, true, true));
		$this->assertSame(QuickIcon::Fine, QuickIcon::state(true, true, false));
		$this->assertSame('danger', QuickIcon::tile(QuickIcon::Inactive, 'x')['class']);
		$this->assertSame('index.php?option=com_bfstop&view=setup&page=proxy', QuickIcon::tile(QuickIcon::Mismatch, 'x')['link']);
		$this->assertSame('index.php?option=com_bfstop', QuickIcon::tile(QuickIcon::Fine, 'x')['link']);

		$app = Factory::getContainer()->get(\Joomla\CMS\Application\AdministratorApplication::class);
		$app->loadIdentity($this->adminUser());
		$app->loadLanguage();
		$app->getLanguage()->load('plg_quickicon_bfstop', dirname(__DIR__, 2).'/quickicon', null, true);
		$tiles = function (string $context = 'update_quickicon') use ($app)
		{
			$plugin = new QuickIcon(array('params' => '{}'));
			$plugin->setApplication($app);
			$event = new QuickIconsEvent('onGetIcons', array('context' => $context));
			$plugin->onGetIcons($event);
			return $event->getArgument('result', array());
		};
		$this->assertSame(array(), $tiles('mod_quickicon'), 'another group of quick icons');
		$_SERVER['REMOTE_ADDR'] = '203.0.113.5';
		unset($_SERVER['HTTP_X_FORWARDED_FOR']);
		$tile = $tiles()[0][0];
		$this->assertSame('plg_quickicon_bfstop', $tile['id']);
		$this->assertSame('danger', $tile['class'], 'the setup is not complete');
		$this->assertSame('index.php?option=com_bfstop&view=setup', $tile['link']);

		$app->loadIdentity(new class () extends \Joomla\CMS\User\User
		{
			public function authorise($action, $assetname = null)
			{
				return $action === 'core.manage';
			}
		});
		$this->assertSame('success', $tiles()[0][0]['class'], 'who may only look at the lists sees the plain tile');
		$app->loadIdentity(new \Joomla\CMS\User\User());
		$this->assertSame(array(), $tiles(), 'nothing for who may not open the component');
	}

	/** Runs Joomla's command line on the installed site; returns its exit status. */
	private function console(string $arguments, &$output = null): int
	{
		exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg(getenv('JOOMLA_ROOT').'/cli/joomla.php').' '.$arguments.' -n 2>&1',
			$lines, $exitCode);
		$output = implode("\n", $lines);
		return $exitCode;
	}

	/**
	 * The console commands, on the installed site: bfstop:setup completes the
	 * setup and activates protection, bfstop:status tells, bfstop:unblock
	 * lifts the block of an address.
	 */
	public function testTheConsoleCommands()
	{
		$this->setPluginEnabled(0);
		$this->assertSame(1, $this->console('bfstop:status', $output), $output);
		$this->assertStringContainsString('not completed', $output);
		$this->assertSame(2, $this->console('bfstop:setup', $output), 'neither --no-proxy nor --trusted');
		$this->assertSame(2, $this->console('bfstop:setup --trusted=10.0.0.5 --header=X-Real-IP', $output), $output);

		self::storeSettings($this->db, json_encode(array('blockMode' => 'off', 'emailaddress' => 'admin@example.org;')));
		$this->assertSame(1, $this->console('bfstop:setup --no-proxy', $output), $output);
		$this->assertStringContainsString('--fix', $output, 'a stored value blocks saving');
		$this->assertSame(1, $this->console('bfstop:setup --no-proxy --fix', $output), 'Reporting Only needs --block-mode');
		$this->assertSame(0, (int) $this->queryValue(self::Enabled));

		$this->assertSame(0, $this->console('bfstop:setup --trusted=10.0.0.5,10.0.0.6 --header=X-Forwarded-For --block-mode=loginonly --fix',
			$output), $output);
		$this->assertSame(1, (int) $this->queryValue(self::Enabled));
		$stored = $this->stored();
		$this->assertSame('1', (string) $stored['useProxy']);
		$this->assertSame("10.0.0.5\n10.0.0.6", $stored['proxyIpAddress']);
		$this->assertSame('loginonly', $stored['blockMode']);
		$this->assertSame('admin@example.org', $stored['emailaddress']);
		$this->assertTrue($this->state()->isCompleted());
		$this->assertSame(0, $this->console('bfstop:status', $output), $output);
		$this->assertStringContainsString('10.0.0.5, 10.0.0.6', $output);

		$this->insert('#__bfstop_bannedip', array('ipaddress' => '10.0.0.5', 'crdate' => self::minutesAgo(1), 'duration' => 0));
		$this->insert('#__bfstop_bannedip', array('ipaddress' => '198.51.100.0/24', 'crdate' => self::minutesAgo(1), 'duration' => 0));
		$blocks = (new Repositories($this->logger))->blocks();
		$this->assertSame(0, $this->console('bfstop:unblock 10.0.0.5', $output), $output);
		$this->assertFalse($blocks->isBlocked('10.0.0.5'));
		$this->assertTrue($blocks->isBlocked('198.51.100.7'));
		$this->assertSame(0, $this->console('bfstop:unblock 198.51.100.7', $output), $output);
		$this->assertFalse($blocks->isBlocked('198.51.100.7'), 'the network the address is in');
		$this->assertSame(2, $this->console('bfstop:unblock nonsense', $output));
	}

	/**
	 * Every page of the assistant renders, for each kind of request, without
	 * a language key left untranslated.
	 */
	public function testThePagesOfTheAssistantRender()
	{
		if (!defined('JPATH_COMPONENT'))
		{
			// the base class of Joomla's views still needs it
			define('JPATH_COMPONENT', JPATH_ADMINISTRATOR.'/components/com_bfstop');
		}
		$app = Factory::getApplication();
		$input = $app->getInput();
		$requests = array(
			'direct' => array('REMOTE_ADDR' => '203.0.113.5', 'SERVER_SOFTWARE' => 'Apache/2.4.58'),
			'proxy' => array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7', 'SERVER_SOFTWARE' => 'nginx/1.25'),
			'cloudflare' => array('REMOTE_ADDR' => '198.51.100.20', 'HTTP_CF_CONNECTING_IP' => '203.0.113.7', 'SERVER_SOFTWARE' => 'LiteSpeed'),
			'unsupported' => array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.7'),
		);
		(new Repositories($this->logger))->state()->set(SetupState::Name, json_encode(array('mode' => 'upgrade', 'from' => '1.5.2',
			'disabled' => 'proxy', 'delays' => 1, 'htaccess' => 1)));
		self::storeSettings($this->db, json_encode(array('blockMode' => 'off', 'emailaddress' => 'a@example.org;')));
		// the toolbar of the page sets the title of the application's document
		$document = Factory::getContainer()->get(\Joomla\CMS\Document\FactoryInterface::class)->createDocument('html');
		$app->loadDocument($document);
		foreach ($requests as $name => $server)
		{
			$_SERVER = $server + $this->originalServer;
			unset($_SERVER['HTTP_X_FORWARDED_FOR']);
			$_SERVER = $server + $_SERVER;
			foreach (SetupModel::Pages as $page)
			{
				$input->set('page', $page);
				$view = new \Codeling\Component\Bfstop\Administrator\View\Setup\HtmlView(array(
					'base_path' => BFSTOP_COMPONENT_ROOT.'/admin', 'template_path' => BFSTOP_COMPONENT_ROOT.'/admin/tmpl/setup'));
				$view->setModel($this->model(), true);
				$view->setDocument($document);
				ob_start();
				try
				{
					$view->display();
				}
				finally
				{
					$html = ob_get_clean();
				}
				$this->assertStringContainsString(\Joomla\CMS\Language\Text::_('COM_BFSTOP_SETUP_PAGE_'.strtoupper($page)), $html, $name.', '.$page);
				$this->assertDoesNotMatchRegularExpression('/\b(COM|PLG)_BFSTOP_[A-Z0-9_]+/', $html, $name.', '.$page);
			}
		}
		$input->set('page', null);
		// as it was: the other tests run without a document
		(new \ReflectionProperty($app, 'document'))->setValue($app, null);
	}
}
