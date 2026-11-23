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
		$this->assertNull($state->noProxyAcknowledged());

		// acknowledged: there is a header, but no proxy in front of the site - which the summary warns about
		$this->assertTrue($this->model()->confirmNoProxy(true, array(), $server), 'acknowledged');
		$this->assertSame('0', (string) $this->stored()['useProxy']);
		$this->assertSame('B', $this->state()->noProxyAcknowledged());
		$this->assertTrue($this->model()->confirmNoProxy(false, array(), array('REMOTE_ADDR' => '203.0.113.5')));
		$this->assertNull($this->state()->noProxyAcknowledged(), 'a direct request: nothing to acknowledge');

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
		$this->assertSame('10.0.0.5, 10.0.0.6', $stored['proxyIpAddress']);
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
		// a proxy, and the update's findings: every page is shown
		self::storeSettings($this->db, json_encode(array('blockMode' => 'off', 'emailaddress' => 'a@example.org;',
			'useProxy' => '1', 'proxyIpAddress' => '10.0.0.5')));
		$this->assertSame(SetupModel::Pages, $this->model()->pages());
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

	/** The page $page of the assistant, as the request $server (with this test's) gets it. */
	private function render(string $page, array $server): string
	{
		if (!defined('JPATH_COMPONENT'))
		{
			define('JPATH_COMPONENT', JPATH_ADMINISTRATOR.'/components/com_bfstop');
		}
		$app = Factory::getApplication();
		$_SERVER = $server + $this->originalServer;
		$document = Factory::getContainer()->get(\Joomla\CMS\Document\FactoryInterface::class)->createDocument('html');
		$app->loadDocument($document);
		$app->getInput()->set('page', $page);
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
			$app->getInput()->set('page', null);
			(new \ReflectionProperty($app, 'document'))->setValue($app, null);
		}
		return $html;
	}

	/**
	 * Before protection is activated, the summary warns where it would lock
	 * the administrator out: their own address (as the saved settings take
	 * it) is blocked - and where they said there is no proxy although their
	 * request came through one.
	 */
	public function testTheSummaryWarnsBeforeTheAdministratorIsLockedOut()
	{
		$direct = array('REMOTE_ADDR' => '203.0.113.5');
		$proxied = array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5');
		self::storeSettings($this->db, json_encode(array('useProxy' => '0')));
		$this->assertNull($this->model()->selfBlocked($direct));
		$this->insert('#__bfstop_bannedip', array('ipaddress' => '203.0.113.0/24', 'crdate' => self::minutesAgo(5), 'duration' => 60));
		$this->assertSame('203.0.113.5', $this->model()->selfBlocked($direct), 'a network block holds it');
		$this->assertNull($this->model()->selfBlocked($proxied), 'without proxy settings: the proxy\'s address');
		$this->assertStringContainsString('id="self-blocked"', $this->render('summary', $direct));

		self::storeSettings($this->db, json_encode(array('useProxy' => '1', 'proxyIpAddress' => '10.0.0.5',
			'proxyHeaderSource' => 'HTTP_X_FORWARDED_FOR')));
		$this->assertSame('203.0.113.5', $this->model()->selfBlocked($proxied), 'the address behind the proxy');
		$this->assertNull($this->model()->selfBlocked(array('HTTP_X_FORWARDED_FOR' => '198.51.100.9') + $proxied));
		$this->insert('#__bfstop_allowlist', array('ipaddress' => '203.0.113.5', 'notes' => 'me'));
		$this->assertNull($this->model()->selfBlocked($proxied), 'the allow list goes first');
		$this->assertStringNotContainsString('id="self-blocked"', $this->render('summary', $proxied));

		self::storeSettings($this->db, json_encode(array('useProxy' => '0')));
		$this->assertTrue($this->model()->confirmNoProxy(true, array(), $proxied));
		$this->assertStringContainsString('id="no-proxy-acknowledged"', $this->render('summary', $proxied));
		self::storeSettings($this->db, json_encode(array('useProxy' => '1', 'proxyIpAddress' => '10.0.0.5')));
		$this->assertStringNotContainsString('id="no-proxy-acknowledged"', $this->render('summary', $proxied),
			'the proxy has been set up since (on the settings page)');
	}

	/**
	 * Behind a CDN other than Cloudflare, the proxy step proposes no address
	 * (the request's is one of the CDN's many servers) and recommends that
	 * the web server resolves the address; several nodes entered are offered
	 * as their narrowest network, which the dry run takes.
	 */
	public function testTheProxyStepBehindACdnAndWithSeveralNodes()
	{
		self::storeSettings($this->db, json_encode(array('useProxy' => '0')));
		$cdn = array('REMOTE_ADDR' => '198.51.100.20', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7');
		$html = $this->render('proxy', $cdn);
		$this->assertStringContainsString(\Joomla\CMS\Language\Text::_('COM_BFSTOP_SETUP_PROXY_CDN_REALIP'), $html);
		$this->assertMatchesRegularExpression('#<textarea[^>]*id="proxy-trusted"[^>]*></textarea>#', $html, 'no address proposed');
		$this->assertStringNotContainsString('198.51.100.20', $html === '' ? '' : preg_replace('#<li>.*?</li>#s', '', $html),
			'the address only as what the request came from');

		$app = Factory::getApplication();
		$app->setUserState(\Codeling\Component\Bfstop\Administrator\Controller\SetupController::ProxyUserState,
			array('choice' => 'proxy', 'header' => 'HTTP_X_FORWARDED_FOR', 'trusted' => "10.0.0.5\n10.0.0.6", 'previewed' => true));
		try
		{
			$html = $this->render('proxy', array('REMOTE_ADDR' => '10.0.0.6', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'));
			$this->assertStringContainsString('id="proxy-network"', $html);
			$this->assertStringContainsString('value="10.0.0.4/30"', $html);
			$this->assertStringContainsString('<code>203.0.113.7</code>', $html, 'the dry run with both nodes');
			$this->assertStringNotContainsString(\Joomla\CMS\Language\Text::_('COM_BFSTOP_SETUP_PROXY_CDN_REALIP'), $html, 'B: no CDN');
		}
		finally
		{
			$app->setUserState(\Codeling\Component\Bfstop\Administrator\Controller\SetupController::ProxyUserState, null);
		}
		$this->assertTrue($this->model()->confirmProxy('HTTP_X_FORWARDED_FOR', '10.0.0.4/30', '203.0.113.7', array(),
			array('REMOTE_ADDR' => '10.0.0.6', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7')), 'the network as the trusted proxies');
	}

	/**
	 * The overview tells how the update's request came where it differs from
	 * this one; the clean-up says when there is nothing to clean up.
	 */
	public function testTheOverviewAndTheCleanUpSayWhatTheyFound()
	{
		(new Repositories($this->logger))->state()->set(SetupState::Name, json_encode(array('mode' => 'upgrade', 'from' => '1.5.2',
			'scenario' => 'B', 'headers' => array('HTTP_X_FORWARDED_FOR'))));
		$expected = strip_tags(\Joomla\CMS\Language\Text::sprintf('COM_BFSTOP_SETUP_OVERVIEW_UPDATE_REQUEST',
			\Joomla\CMS\Language\Text::_('COM_BFSTOP_SETUP_SCENARIO_B'), 'X-Forwarded-For'));
		$html = $this->render('overview', array('REMOTE_ADDR' => '203.0.113.5'));
		$this->assertStringContainsString($expected, html_entity_decode(strip_tags($html), ENT_QUOTES));
		$html = $this->render('overview', array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'));
		$this->assertStringNotContainsString($expected, html_entity_decode(strip_tags($html), ENT_QUOTES), 'the same way as this one');

		self::storeSettings($this->db, json_encode(array('useProxy' => '1', 'proxyIpAddress' => '10.0.0.5')));
		$this->assertStringContainsString(\Joomla\CMS\Language\Text::_('COM_BFSTOP_SETUP_CLEANUP_NOTHING'),
			$this->render('cleanup', array('REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7')));
	}

	/** The pages which only make sense after an update are shown only then. */
	public function testThePagesDependOnTheSite()
	{
		$state = (new Repositories($this->logger))->state();
		$state->set(SetupState::Name, json_encode(array('mode' => 'install')));
		self::storeSettings($this->db, json_encode(array('htaccessPath' => sys_get_temp_dir().'/bfstop-no-such-dir')));
		$this->assertSame(array('overview', 'proxy', 'blockmode', 'notify', 'parts', 'scheduler', 'summary'), $this->model()->pages());
		$this->assertSame('blockmode', $this->model()->nextPage('proxy'));
		$this->assertSame('summary', $this->model()->nextPage('summary'));
		$state->set(SetupState::Name, json_encode(array('mode' => 'upgrade', 'from' => '1.5.2')));
		$this->assertSame(array('overview', 'proxy', 'blockmode', 'notify', 'parts', 'privacy', 'scheduler', 'summary'),
			$this->model()->pages(), 'no proxy, no delays, no .htaccess section of 1.x');
		$state->set(SetupState::Name, json_encode(array('mode' => 'upgrade', 'from' => '1.5.2', 'delays' => 1)));
		self::storeSettings($this->db, json_encode(array('useProxy' => '1', 'proxyIpAddress' => '10.0.0.5')));
		$this->assertSame(array('overview', 'proxy', 'cleanup', 'blockmode', 'notify', 'parts', 'privacy', 'ratelimit',
			'scheduler', 'summary'), $this->model()->pages());
	}

	/** Optional steps can be skipped, the required ones not. */
	public function testSkippingAndAcknowledging()
	{
		$model = $this->model();
		$this->assertTrue($model->skip(SetupState::StepNotify));
		$this->assertFalse($model->skip(SetupState::StepProxy), 'required');
		$this->assertFalse($model->skip('nonsense'));
		$this->assertTrue($model->acknowledge(SetupState::StepRateLimit));
		$this->assertFalse($model->acknowledge(SetupState::StepNotify), 'a step of settings is saved');
		$state = $this->state();
		$this->assertSame(SetupState::Skipped, $state->status(SetupState::StepNotify));
		$this->assertSame(SetupState::Done, $state->status(SetupState::StepRateLimit));
		$this->assertSame(SetupState::RequiredSteps, $state->pendingRequiredSteps(), 'optional steps hold nothing back');
	}

	/**
	 * After the proxy fix: the blocks of the proxy are lifted, its failed
	 * logins, offences and remembered logins removed; the allow list's
	 * entries which contain it are only shown.
	 */
	public function testTheCleanUpAfterTheProxyFix()
	{
		self::storeSettings($this->db, json_encode(array('useProxy' => '1', 'proxyIpAddress' => "10.0.0.5\n198.51.100.0/24")));
		$this->insert('#__bfstop_bannedip', array('ipaddress' => '10.0.0.5', 'crdate' => self::minutesAgo(5), 'duration' => 0));
		$this->insert('#__bfstop_bannedip', array('ipaddress' => '198.51.100.7', 'crdate' => self::minutesAgo(5), 'duration' => 60));
		$this->insert('#__bfstop_bannedip', array('ipaddress' => '203.0.113.9', 'crdate' => self::minutesAgo(5), 'duration' => 60));
		foreach (array('10.0.0.5', '10.0.0.5', '198.51.100.7', '203.0.113.9') as $ip)
		{
			$this->insert('#__bfstop_failedlogin', array('ipaddress' => $ip, 'logtime' => self::minutesAgo(1), 'username' => 'bob', 'origin' => 0));
		}
		$this->insert('#__bfstop_offence', array('ipaddress' => '10.0.0.5', 'blocks' => 2, 'last_block' => self::minutesAgo(60)));
		$this->insert('#__bfstop_offence', array('ipaddress' => '203.0.113.9', 'blocks' => 1, 'last_block' => self::minutesAgo(60)));
		$this->insert('#__bfstop_knownip', array('ipaddress' => '10.0.0.5', 'username' => 'alice',
			'first_success' => self::minutesAgo(60), 'last_success' => self::minutesAgo(1)));
		$this->insert('#__bfstop_allowlist', array('ipaddress' => '10.0.0.0/24', 'notes' => 'the proxy'));

		$this->assertSame(array('10.0.0.5', '198.51.100.7'), array_values(array_intersect(array('10.0.0.5', '198.51.100.7'),
			$this->model()->suspiciousBlocks(array('REMOTE_ADDR' => '198.51.100.7')))), 'private, and the request\'s own');
		$findings = $this->model()->cleanupFindings();
		$this->assertEqualsCanonicalizing(array('10.0.0.5', '198.51.100.7'), $findings['blocks']);
		$this->assertSame(array('10.0.0.5' => 2, '198.51.100.7' => 1), $findings['failedLogins']);
		$this->assertSame(array('10.0.0.5'), $findings['offences']);
		$this->assertSame(array('10.0.0.5'), $findings['knownIps']);
		$this->assertSame(array('10.0.0.0/24'), $findings['allowList']);

		$this->assertTrue($this->model()->cleanup());
		$blocks = (new Repositories($this->logger))->blocks();
		$this->assertFalse($blocks->isBlocked('10.0.0.5'));
		$this->assertFalse($blocks->isBlocked('198.51.100.7'));
		$this->assertTrue($blocks->isBlocked('203.0.113.9'), 'not a proxy');
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'));
		$this->assertSame('203.0.113.9', $this->queryValue('SELECT ipaddress FROM #__bfstop_offence'));
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip'));
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_allowlist'), 'the administrator\'s to change');
		$this->assertSame(SetupState::Done, $this->state()->status(SetupState::StepCleanup));
		$this->assertFalse(\Codeling\Library\Bfstop\Service\Setup\ProxyCleanup::anything(
			array('allowList' => array()) + $this->model()->cleanupFindings()));

		self::storeSettings($this->db, json_encode(array('useProxy' => '0')));
		$model = $this->model();
		$this->assertFalse($model->cleanup(), 'no proxy configured');
	}

	/** The block section of 1.x in .htaccess, shown as it is and as it would be, and rewritten. */
	public function testTheLegacyHtaccessStep()
	{
		$dir = sys_get_temp_dir().'/bfstop-legacy-'.bin2hex(random_bytes(4));
		mkdir($dir);
		try
		{
			file_put_contents($dir.'/.htaccess', "RewriteEngine On\n# BEGIN BFStop Blocks\n<RequireAll>\nRequire all granted\n".
				"Require not ip 203.0.113.5\n</RequireAll>\n# END BFStop Blocks\n");
			self::storeSettings($this->db, json_encode(array('htaccessPath' => $dir)));
			(new Repositories($this->logger))->state()->set(SetupState::Name, json_encode(array('mode' => 'upgrade', 'from' => '1.5.2')));
			$model = $this->model();
			$this->assertContains('htaccess', $model->pages());
			$legacy = $model->legacyHtaccess();
			$this->assertTrue($legacy['present']);
			$this->assertContains('Require all granted', $legacy['current']);
			$this->assertNotContains('Require all granted', $legacy['proposed']);
			$this->assertStringContainsString("-R '203.0.113.5'", implode("\n", $legacy['proposed']));

			$this->assertTrue($model->upgradeHtaccess(), implode(' ', array_map('strval', $model->getErrors())));
			$this->assertStringNotContainsString('Require all granted', file_get_contents($dir.'/.htaccess'));
			$this->assertStringContainsString('RewriteEngine On', file_get_contents($dir.'/.htaccess'));
			$this->assertFalse($this->model()->legacyHtaccess()['present']);
			$this->assertNotContains('htaccess', $this->model()->pages(), 'nothing left of 1.x');
			$this->assertSame(SetupState::Done, $this->state()->status(SetupState::StepHtaccess));
		}
		finally
		{
			@unlink($dir.'/.htaccess');
			@rmdir($dir);
		}
	}

	/**
	 * The steps of settings save their own settings only, through the
	 * settings model; the changed meaning of the unblock mails of 1.x is
	 * decided with the notifications.
	 */
	public function testTheStepsOfSettings()
	{
		Factory::getApplication()->set('live_site', 'https://www.example.org');
		try
		{
			self::storeSettings($this->db, json_encode(array('notifyBlockedUser' => '1', 'blockNumber' => '7')));
			(new Repositories($this->logger))->state()->set(SetupState::Name, json_encode(array('mode' => 'upgrade', 'from' => '1.5.2')));
			$model = $this->model();
			$this->assertTrue($model->notifyMeaningChanged());
			$this->assertTrue($model->saveFields(SetupState::StepNotify, array('emailaddress' => 'security@example.org',
				'notifyBlockedUser' => '1', 'blockNumber' => '3'), array()), self::errors($model));
			$stored = $this->stored();
			$this->assertSame('security@example.org', $stored['emailaddress']);
			$this->assertSame('7', (string) $stored['blockNumber'], 'not a setting of this step');
			$state = $this->state();
			$this->assertSame(SetupState::Done, $state->status(SetupState::StepNotify));
			$this->assertSame(SetupState::Done, $state->status(SetupState::StepNotifyMeaning));

			$model = $this->model();
			$this->assertFalse($model->saveFields(SetupState::StepParts, array('enabledForOrigin' => array()), array()));
			$this->assertTrue($model->saveFields(SetupState::StepParts, array('enabledForOrigin' => array('1', '4')), array()),
				self::errors($model));
			$this->assertSame(5, (int) $this->stored()['enabledForOrigin']);
			$this->assertTrue($this->model()->saveFields(SetupState::StepPrivacy, array('deleteOld' => '8'), array()));
			$this->assertSame('8', (string) $this->stored()['deleteOld']);
			$this->assertFalse($this->model()->saveFields('proxy', array('useProxy' => '1'), array()), 'not a step of settings');
			$this->assertGreaterThanOrEqual(0, $this->model()->apiTokenUsers());
		}
		finally
		{
			Factory::getApplication()->set('live_site', '');
		}
	}

	/**
	 * The plain usernames of 1.x are hashed on request, in rounds: not those
	 * of accounts or the common ones; statistics which end up with the same
	 * hash are merged.
	 */
	public function testHashingTheUsernamesOf1x()
	{
		$secret = (string) Factory::getApplication()->get('secret', '');
		$hash = fn ($name) => \Codeling\Library\Bfstop\Helper\UsernameHelper::forStorage($name, 'hash', false, $secret);
		foreach (array('Admin', 'root', 'my-Secret-password', $hash('other')) as $i => $name)
		{
			$this->insert('#__bfstop_failedlogin', array('ipaddress' => '203.0.113.'.$i, 'logtime' => self::minutesAgo(1),
				'username' => $name, 'origin' => 0));
		}
		$this->insert('#__bfstop_username_stats', array('username' => 'my-secret-password', 'attempts' => 2,
			'first_attempt' => '2024-01-01 10:00:00', 'last_attempt' => '2024-01-05 10:00:00'));
		$this->insert('#__bfstop_username_stats', array('username' => $hash('my-secret-password'), 'attempts' => 3,
			'first_attempt' => '2025-01-01 10:00:00', 'last_attempt' => '2025-02-01 10:00:00'));
		$this->insert('#__bfstop_username_stats', array('username' => 'Admin', 'attempts' => 1,
			'first_attempt' => '2024-01-01 10:00:00', 'last_attempt' => '2024-01-01 10:00:00'));

		$model = $this->model();
		$progress = array('table' => '', 'after' => '');
		for ($i = 0; $i < 10; ++$i)
		{
			$progress = $model->hashUsernames((string) $progress['table'], (string) $progress['after'], 0.0);
			if ($progress['done'])
			{
				break;
			}
		}
		$this->assertTrue($progress['done']);
		$this->db->setQuery('SELECT username FROM #__bfstop_failedlogin ORDER BY ipaddress');
		$this->assertSame(array('Admin', 'root', $hash('my-Secret-password'), $hash('other')), $this->db->loadColumn());
		$this->db->setQuery('SELECT username, attempts, first_attempt, last_attempt FROM #__bfstop_username_stats ORDER BY username');
		$stats = $this->db->loadAssocList('username');
		$this->assertCount(2, $stats);
		$merged = $stats[$hash('my-secret-password')];
		$this->assertSame(5, (int) $merged['attempts']);
		$this->assertStringStartsWith('2024-01-01', (string) $merged['first_attempt']);
		$this->assertStringStartsWith('2025-02-01', (string) $merged['last_attempt']);
		$this->assertArrayHasKey('Admin', $stats);
		$this->assertTrue(\Codeling\Library\Bfstop\Service\Setup\UsernameHashing::isHashed($hash('x')));
		$this->assertSame(1, $this->model()->privacyFacts()['count'] > 0 ? 1 : 0);
	}

	/** What the scheduler step shows of the installed site. */
	public function testTheSchedulerFacts()
	{
		$facts = $this->model()->schedulerFacts();
		$this->assertTrue($facts['plugin'], 'the package installs the task plugin switched on');
		$this->assertCount(1, $facts['tasks']);
		$this->assertSame('Brute Force Stop maintenance', $facts['tasks'][0]->title);
		$this->assertIsBool($facts['lazy']);
	}

	/**
	 * Trusted proxies stored by the assistant (a list of several lines, as
	 * the Cloudflare ranges come) survive the settings page: its field is one
	 * line, from which a browser drops line breaks - a list stored with them
	 * would come back glued together, and no later save would validate.
	 */
	public function testTrustedProxiesStoredByTheAssistantSurviveTheSettingsPage()
	{
		$server = array('REMOTE_ADDR' => '173.245.48.9', 'HTTP_CF_CONNECTING_IP' => '203.0.113.7');
		$model = $this->model();
		$this->assertTrue($model->confirmProxy(\Codeling\Library\Bfstop\Helper\IpHelper::CloudflareHeader,
			"173.245.48.0/20\n103.21.244.0/22\r\n2400:cb00::/32", '203.0.113.7', array(), $server), self::errors($model));
		$stored = $this->stored();
		$this->assertSame('173.245.48.0/20, 103.21.244.0/22, 2400:cb00::/32', $stored['proxyIpAddress']);

		// the field as the settings page renders it, and what a browser posts of it
		$form = \Codeling\Component\Bfstop\Administrator\Model\SettingsModel::settingsForm();
		$form->bind(array('params' => \Codeling\Component\Bfstop\Administrator\Model\SettingsModel::paramsForForm($stored)));
		$this->assertMatchesRegularExpression('/<input[^>]*type="text"[^>]*value="([^"]*)"/', $form->getInput('proxyIpAddress', 'params'));
		preg_match('/value="([^"]*)"/', $form->getInput('proxyIpAddress', 'params'), $m);
		$posted = str_replace(array("\r", "\n"), '', html_entity_decode($m[1], ENT_QUOTES, 'UTF-8'));
		$this->assertSame($stored['proxyIpAddress'], $posted);

		$settings = new \Codeling\Component\Bfstop\Administrator\Model\SettingsModel(array('ignore_request' => true),
			new MVCFactory('Codeling\\Component\\Bfstop'));
		$settings->setDatabase($this->db);
		$valid = $settings->validate(\Codeling\Component\Bfstop\Administrator\Model\SettingsModel::settingsForm(),
			array('params' => \Codeling\Component\Bfstop\Administrator\Model\SettingsModel::paramsForForm(
				array('proxyIpAddress' => $posted) + $stored)));
		$this->assertIsArray($valid, implode(' ', array_map('strval', $settings->getErrors())));
		$this->assertSame(array('173.245.48.0/20', '103.21.244.0/22', '2400:cb00::/32'),
			\Codeling\Library\Bfstop\Helper\IpHelper::parseTrustedProxies($valid['params']['proxyIpAddress']));
	}

	/**
	 * Whether a username of 1.x is an account's - and stays readable - is
	 * decided as the login decides it (UserRepository::accountExists()),
	 * whatever the database's collation: MySQL's utf8mb4_unicode_ci takes
	 * "muller", "müller" and "Müller" for the same name, PostgreSQL doesn't.
	 * And only the spelling decided about is renamed: on MySQL, renaming
	 * "muller" must not rename "müller" with it.
	 */
	public function testHashingDecidesAsTheLoginWhateverTheCollation()
	{
		$secret = (string) Factory::getApplication()->get('secret', '');
		$hash = fn ($name) => \Codeling\Library\Bfstop\Helper\UsernameHelper::forStorage($name, 'hash', false, $secret);
		$userId = $this->insert('#__users', array('name' => 'Müller', 'username' => 'müller', 'email' => 'mueller@example.org',
			'password' => '', 'registerDate' => self::minutesAgo(0), 'params' => '{}', 'block' => 0), 'id');
		try
		{
			$names = array('muller', 'müller', 'Müller', 'stranger-pw', 'mueller@example.org');
			foreach ($names as $i => $name)
			{
				$this->insert('#__bfstop_failedlogin', array('ipaddress' => '203.0.113.'.($i + 10), 'logtime' => self::minutesAgo(1),
					'username' => $name, 'origin' => 0));
			}
			$users = (new Repositories($this->logger))->users();
			$expected = array_map(fn ($name) => $users->accountExists($name) ? $name : $hash($name), $names);
			$this->assertSame('müller', $expected[1], 'the account itself');
			$this->assertSame($hash('stranger-pw'), $expected[3]);

			$model = $this->model();
			$progress = array('table' => '', 'after' => '');
			for ($round = 0; $round < 10 && empty($progress['done']); ++$round)
			{
				$progress = $model->hashUsernames((string) $progress['table'], (string) $progress['after'], 0.0);
			}
			$this->assertTrue($progress['done']);
			$this->db->setQuery('SELECT username FROM #__bfstop_failedlogin ORDER BY ipaddress');
			$this->assertSame($expected, $this->db->loadColumn(), $this->db->getServerType());
		}
		finally
		{
			$this->db->setQuery('DELETE FROM #__users WHERE id='.(int) $userId)->execute();
		}
	}
}
