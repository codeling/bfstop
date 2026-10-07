<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Component\Bfstop\Administrator\Controller\DisplayController;
use Codeling\Component\Bfstop\Administrator\Helper\IpValidateHelper;
use Codeling\Component\Bfstop\Administrator\Helper\UnblockHelper;
use Codeling\Component\Bfstop\Administrator\Model\AllowModel;
use Codeling\Component\Bfstop\Administrator\Model\AllowlistModel;
use Codeling\Component\Bfstop\Administrator\Model\BlockModel;
use Codeling\Component\Bfstop\Administrator\Model\BlocklistModel;
use Codeling\Component\Bfstop\Administrator\Model\FailedloginlistModel;
use Codeling\Component\Bfstop\Administrator\Model\UsernamestatsModel;
use Codeling\Component\Bfstop\Site\Model\TokenunblockModel;
use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Factory\MVCFactory;

/**
 * Database access of the component (https://github.com/codeling/com_bfstop),
 * loaded from the checkout given in COM_BFSTOP_ROOT.
 */
class ComponentTest extends IntegrationTestCase
{
	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		if (!getenv('COM_BFSTOP_ROOT'))
		{
			self::markTestSkipped('COM_BFSTOP_ROOT not set, see tests/README.md');
		}
	}

	private function model($class)
	{
		$model = new $class(array('dbo' => $this->db), new MVCFactory('Codeling\\Component\\Bfstop'));
		$model->setDatabase($this->db);
		return $model;
	}

	private function listCount($class)
	{
		$model = $this->model($class);
		$getListQuery = new \ReflectionMethod($model, 'getListQuery');
		$this->db->setQuery($getListQuery->invoke($model));
		return count($this->db->loadObjectList());
	}

	/**
	 * Saves a new entry like the component's edit views do; the id comes
	 * empty from the form when creating a new entry
	 */
	private function saveNew($modelClass, array $data)
	{
		$model = $this->model($modelClass);
		$model->getState(); // populate the state now, so it doesn't overwrite the saved id later
		$this->assertTrue($model->save(array('id' => '') + $data), implode(', ', $model->getErrors()));
		return (int) $model->getState($model->getName().'.id');
	}

	public function testTablesAndListViews()
	{
		$blockId = $this->saveNew(BlockModel::class,
			array('ipaddress' => '192.0.2.0/24', 'crdate' => '2026-01-02', 'duration' => '0'));
		$allowId = $this->saveNew(AllowModel::class,
			array('ipaddress' => '198.51.100.0/24', 'notes' => 'test'));
		$this->assertGreaterThan(0, $blockId);
		$this->assertGreaterThan(0, $allowId);
		$this->insert('#__bfstop_unblock', array('block_id' => $blockId, 'source' => 0, 'crdate' => self::minutesAgo(0)));
		$this->insert('#__bfstop_failedlogin', array('ipaddress' => '192.0.2.1', 'logtime' => self::minutesAgo(0), 'username' => 'bob', 'origin' => 0));

		$this->assertSame(1, $this->listCount(BlocklistModel::class));
		$this->assertSame(1, $this->listCount(AllowlistModel::class));
		$this->assertSame(1, $this->listCount(FailedloginlistModel::class));

		$this->model(AllowlistModel::class)->remove(array($allowId), $this->logger);
		$this->assertSame(0, $this->listCount(AllowlistModel::class));
	}

	public function testPurgeFailedLogins()
	{
		$this->insert('#__bfstop_failedlogin', array('ipaddress' => '192.0.2.1', 'logtime' => self::minutesAgo(31 * 24 * 60), 'username' => 'old', 'origin' => 0));
		$this->insert('#__bfstop_failedlogin', array('ipaddress' => '192.0.2.1', 'logtime' => self::minutesAgo(0), 'username' => 'new', 'origin' => 0));
		$this->assertSame(1, $this->model(FailedloginlistModel::class)->purgeOlderThan(30));
		$this->assertSame('new', $this->queryValue('SELECT username FROM #__bfstop_failedlogin'));
	}

	public function testUsernameStatistics()
	{
		$this->insert('#__bfstop_username_stats', array('username' => 'Admin', 'attempts' => 12,
			'first_attempt' => self::minutesAgo(3 * 24 * 60), 'last_attempt' => self::minutesAgo(60)));
		$this->insert('#__bfstop_username_stats', array('username' => 'old', 'attempts' => 3,
			'first_attempt' => self::minutesAgo(40 * 24 * 60), 'last_attempt' => self::minutesAgo(31 * 24 * 60)));

		$this->assertSame(2, $this->listCount(UsernamestatsModel::class));
		$model = $this->model(UsernamestatsModel::class);
		$this->assertSame(12, $model->getMaxAttempts());
		$this->assertSame(1, $model->purgeNotSeenFor(30));
		$this->assertSame('Admin', $this->queryValue('SELECT username FROM #__bfstop_username_stats'));
	}

	public function testUnblockViaEmailToken()
	{
		$blockId = $this->insert('#__bfstop_bannedip', array('ipaddress' => '203.0.113.5', 'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		$this->insert('#__bfstop_unblock_token', array('token' => 'expired', 'block_id' => $blockId, 'crdate' => self::minutesAgo(4 * 24 * 60)));
		$this->insert('#__bfstop_unblock_token', array('token' => 'valid', 'block_id' => $blockId, 'crdate' => self::minutesAgo(60)));
		$helper = new DatabaseHelper($this->logger);
		$this->assertTrue($helper->isIPBlocked('203.0.113.5'));

		$model = $this->model(TokenunblockModel::class);
		$this->assertFalse((bool) $model->unblock('expired', $this->logger), 'expired token must not unblock');
		$this->logger->errors = array(); // expected: "token not found" error
		$this->assertTrue((bool) $model->unblock('valid', $this->logger));

		$this->assertFalse($helper->isIPBlocked('203.0.113.5'));
		$this->assertSame(1, (int) $this->queryValue('SELECT source FROM #__bfstop_unblock WHERE block_id='.$blockId));
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock_token'));
	}

	public function testTokenUnblockNeedsConfirmationAndTheBlockedIp()
	{
		$ip = '203.0.113.5';
		$blockId = $this->insert('#__bfstop_bannedip', array('ipaddress' => $ip, 'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		$this->insert('#__bfstop_unblock_token', array('token' => 'valid', 'block_id' => $blockId, 'crdate' => self::minutesAgo(60)));
		$helper = new DatabaseHelper($this->logger);
		$model = $this->model(TokenunblockModel::class);
		$tokens = 'SELECT COUNT(*) FROM #__bfstop_unblock_token';

		$this->assertSame(TokenunblockModel::ResultInvalid, $model->process('', true, $ip, $this->logger));

		// opening the link (what a mail scanner does) changes nothing
		$this->assertSame(TokenunblockModel::ResultConfirm, $model->process('valid', false, $ip, $this->logger));
		$this->assertTrue($helper->isIPBlocked($ip));
		$this->assertSame(1, (int) $this->queryValue($tokens));

		// confirming from another IP address doesn't unblock either
		$this->assertSame(TokenunblockModel::ResultWrongIp, $model->process('valid', true, '198.51.100.9', $this->logger));
		$this->assertTrue($helper->isIPBlocked($ip));
		$this->assertSame(1, (int) $this->queryValue($tokens));

		// neither does an unknown token
		$this->assertSame(TokenunblockModel::ResultNotFound, $model->process('unknown', true, $ip, $this->logger));
		$this->logger->errors = array(); // expected: "token not found" error
		$this->assertTrue($helper->isIPBlocked($ip));

		$this->assertSame(TokenunblockModel::ResultUnblocked, $model->process('valid', true, $ip, $this->logger));
		$this->assertFalse($helper->isIPBlocked($ip));
		$this->assertSame(0, (int) $this->queryValue($tokens));
	}

	public function testTokenUnblockHttpStatus()
	{
		$this->assertSame(400, TokenunblockModel::httpStatus(TokenunblockModel::ResultInvalid));
		$this->assertSame(403, TokenunblockModel::httpStatus(TokenunblockModel::ResultWrongIp));
		$this->assertSame(404, TokenunblockModel::httpStatus(TokenunblockModel::ResultNotFound));
		$this->assertSame(500, TokenunblockModel::httpStatus(TokenunblockModel::ResultFailed));
		// opening the link only asks for confirmation, whatever the token is
		$this->assertSame(200, TokenunblockModel::httpStatus(TokenunblockModel::ResultConfirm));
		$this->assertSame(200, TokenunblockModel::httpStatus(TokenunblockModel::ResultUnblocked));
	}

	public function testExpiredAndUsedTokensAreNotFound()
	{
		$ip = '203.0.113.5';
		$blockId = $this->insert('#__bfstop_bannedip', array('ipaddress' => $ip, 'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		$this->insert('#__bfstop_unblock_token', array('token' => 'expired', 'block_id' => $blockId, 'crdate' => self::minutesAgo(4 * 24 * 60)));
		$this->insert('#__bfstop_unblock_token', array('token' => 'used', 'block_id' => $blockId, 'crdate' => self::minutesAgo(10)));
		$model = $this->model(TokenunblockModel::class);
		$this->assertSame(TokenunblockModel::ResultUnblocked, $model->process('used', true, $ip, $this->logger));
		$this->assertSame(TokenunblockModel::ResultNotFound, $model->process('used', true, $ip, $this->logger), 'used up');
		$this->assertSame(TokenunblockModel::ResultNotFound, $model->process('expired', true, $ip, $this->logger));
		$this->logger->errors = array(); // expected: "token not found" errors
	}

	public function testTokenUnblockComparesIpv6AddressesNotSpellings()
	{
		$blockId = $this->insert('#__bfstop_bannedip', array('ipaddress' => '2001:db8::1', 'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		$this->insert('#__bfstop_unblock_token', array('token' => 'valid', 'block_id' => $blockId, 'crdate' => self::minutesAgo(1)));
		$model = $this->model(TokenunblockModel::class);
		$this->assertSame(TokenunblockModel::ResultWrongIp, $model->process('valid', true, '2001:db8::2', $this->logger));
		$this->assertSame(TokenunblockModel::ResultUnblocked, $model->process('valid', true, '2001:0DB8:0:0:0:0:0:1', $this->logger));
	}

	public function testLogViewEscapesLogContents()
	{
		// the message of a log entry can contain what a visitor sent (e.g. a username)
		$view = new class {
			public $items;
			public function escape($string)
			{
				return htmlspecialchars((string) $string, ENT_QUOTES, 'UTF-8');
			}
		};
		$view->items = array((object) array('date' => '2026-01-01T00:00:00+00:00',
			'priority' => 'DEBUG', 'message' => 'Unknown user (<script>alert(1)</script>) blocked'));
		ob_start();
		(function ()
		{
			include getenv('COM_BFSTOP_ROOT').'/admin/tmpl/log/default_body.php';
		})->call($view);
		$html = ob_get_clean();
		$this->assertStringNotContainsString('<script>', $html);
		$this->assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $html);
	}

	public function testTokenUnblockForBlockedIpv6Network()
	{
		$blockId = $this->insert('#__bfstop_bannedip', array('ipaddress' => '2001:db8:1:2::/64', 'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		$this->insert('#__bfstop_unblock_token', array('token' => 'valid', 'block_id' => $blockId, 'crdate' => self::minutesAgo(1)));
		$model = $this->model(TokenunblockModel::class);
		$this->assertSame(TokenunblockModel::ResultWrongIp, $model->process('valid', true, '2001:db8:1:3::1', $this->logger));
		$this->assertSame(TokenunblockModel::ResultWrongIp, $model->process('valid', true, '203.0.113.5', $this->logger));
		$this->assertSame(TokenunblockModel::ResultUnblocked, $model->process('valid', true, '2001:db8:1:2:abcd::77', $this->logger));
	}

	private function formRuleResult($ruleFile, $class, $value, $blockMode = 'full')
	{
		if (!class_exists($class, false))
		{
			require_once getenv('COM_BFSTOP_ROOT').'/admin/rules/'.$ruleFile;
		}
		$rule = new $class();
		return $rule->test(new \SimpleXMLElement('<field name="x" />'), $value, null,
			new \Joomla\Registry\Registry(array('params' => array('blockMode' => $blockMode))));
	}

	public function testHtaccessPathRule()
	{
		$test = fn ($value, $mode = 'full') => $this->formRuleResult('htaccesspath.php', 'JFormRuleHtaccesspath', $value, $mode);
		$this->assertTrue($test(''));
		$this->assertTrue($test(sys_get_temp_dir(), 'htaccess'));
		$this->assertTrue($test('/does/not/exist', 'full'), 'only has to exist if .htaccess is used for blocking');
		$this->assertInstanceOf(\UnexpectedValueException::class, $test('/does/not/exist', 'htaccess'));
		foreach (array('phar:///tmp/x.phar', 'ftp://example.org/', "/tmp\n", "/tmp\0") as $path)
		{
			$this->assertInstanceOf(\UnexpectedValueException::class, $test($path, 'full'), $path);
			$this->assertInstanceOf(\UnexpectedValueException::class, $test($path, 'htaccess'), $path);
		}
	}

	public function testGeoDbPathRule()
	{
		$test = fn ($value) => $this->formRuleResult('geodbpath.php', 'JFormRuleGeodbpath', $value);
		$this->assertTrue($test(''));
		$this->assertTrue($test('/var/lib/GeoLite2-City.mmdb'));
		$this->assertTrue($test('relative/path/GeoLite2-Country.MMDB'));
		foreach (array('/var/lib/GeoLite2.txt', '/etc/passwd', 'phar:///tmp/x.phar/y.mmdb', 'file:///etc/x.mmdb',
			"/x/y.mmdb\n", "/x/y.mmdb\0.txt", '/x/y.mmdb.php') as $path)
		{
			$this->assertInstanceOf(\UnexpectedValueException::class, $test($path), $path);
		}
	}

	public function testWarnsAboutAdminUserCaseInsensitively()
	{
		// tests/ci/install-joomla.sh creates the super user as "Admin"
		$app = Factory::getApplication();
		$app->getMessageQueue(true);
		$controller = new DisplayController(array('base_path' => JPATH_ADMINISTRATOR.'/components/com_bfstop'), new MVCFactory('Codeling\\Component\\Bfstop'), $app, $app->getInput());
		$controller->warnIfAdminUserExists();
		$this->assertCount(1, $app->getMessageQueue(true));
	}

	public function testMessagesEscapeWhatWasTypedIn()
	{
		// Joomla shows the messages as HTML
		$app = Factory::getApplication();
		Factory::getLanguage()->load('com_bfstop', getenv('COM_BFSTOP_ROOT').'/admin');
		$app->getMessageQueue(true);
		$evil = '<script>alert(1)</script>';
		$this->assertFalse(IpValidateHelper::validIPRange($evil));
		$this->assertFalse(IpValidateHelper::validIPRange('203.0.113.0/'.$evil));
		IpValidateHelper::validIPRange('10.0.0.1'); // private: a warning with the address
		$messages = '';
		foreach ($app->getMessageQueue(true) as $message)
		{
			$messages .= $message['message'];
		}
		$this->assertStringNotContainsString('<script>', $messages);
		$this->assertStringContainsString('&lt;script&gt;', $messages);
	}

	private function settingsForm()
	{
		$form = new \Joomla\CMS\Form\Form('com_bfstop.settings');
		$form->addRulePath(getenv('COM_BFSTOP_ROOT').'/admin/rules');
		$form->loadFile(getenv('COM_BFSTOP_ROOT').'/admin/forms/settings.xml');
		return $form;
	}

	public function testSettingsOnlyTakeTheValuesTheyOffer()
	{
		$form = $this->settingsForm();
		$this->assertTrue($form->validate(array('params' => array('blockMode' => 'htaccess', 'blockNumber' => '10',
			'delayDuration' => '20', 'emailaddress' => 'a@example.org; b@example.org'))));
		foreach (array('blockMode' => 'everything', 'delayDuration' => '100000', 'blockNumber' => '-3',
			'ipv6PrefixLength' => '0', 'unknownUsernameMode' => 'x', 'maxBlocksBefore' => '7') as $name => $value)
		{
			$this->assertFalse($this->settingsForm()->validate(array('params' => array($name => $value))), "$name=$value");
		}
	}

	public function testEveryListAndIntegerSettingIsValidatedAgainstItsOptions()
	{
		$xml = simplexml_load_file(getenv('COM_BFSTOP_ROOT').'/admin/forms/settings.xml');
		$fields = $xml->xpath('//field[@type="list" or @type="integer"]');
		$this->assertGreaterThan(30, count($fields));
		foreach ($fields as $field)
		{
			$this->assertSame('options', (string) $field['validate'], (string) $field['name']);
		}
		// no two options of a list with the same value
		foreach ($xml->xpath('//field[@type="list"]') as $field)
		{
			$values = array();
			foreach ($field->option as $option)
			{
				$values[] = (string) $option['value'];
			}
			$this->assertSame($values, array_values(array_unique($values)), (string) $field['name']);
		}
	}

	public function testNotificationAddressesAreChecked()
	{
		$test = fn ($value) => $this->formRuleResult('emaillist.php', 'JFormRuleEmaillist', $value);
		$this->assertTrue($test(''));
		$this->assertTrue($test('a@example.org'));
		$this->assertTrue($test(' a@example.org ; b@example.org '));
		foreach (array('a@example.org;', 'nobody', "a@example.org\r\nBcc: x@example.org", 'a@example.org,b@example.org') as $value)
		{
			$this->assertInstanceOf(\UnexpectedValueException::class, $test($value), $value);
		}
		$message = $test('<b>x</b>')->getMessage();
		$this->assertStringNotContainsString('<b>', $message);
	}

	public function testRemovingFromTheAllowlist()
	{
		$a = $this->insert('#__bfstop_allowlist', array('ipaddress' => '203.0.113.1', 'notes' => ''), 'id');
		$b = $this->insert('#__bfstop_allowlist', array('ipaddress' => '203.0.113.2', 'notes' => ''), 'id');
		$model = $this->model(AllowlistModel::class);
		// whatever the request sent in cid[] is made into numbers: only $a is meant
		$message = $model->remove(array((string) $a, 'x', '0; DELETE FROM #__bfstop_allowlist'), $this->logger);
		$this->assertNotSame('', $message);
		$this->assertSame(array('203.0.113.2'), $this->db->setQuery('SELECT ipaddress FROM #__bfstop_allowlist')->loadColumn());
		$this->assertNotSame($message, $model->remove(array(), $this->logger));
	}

	public function testUnblockWithoutResultStillReportsFailure()
	{
		// an exception while unblocking must not leave the result undefined
		$this->assertFalse(UnblockHelper::unblockDB($this->db, array(), 0, $this->logger));
		$this->assertTrue($this->logger->hasMessage(\Joomla\CMS\Log\Log::ERROR, 'Invalid parameter'));
		$this->logger->errors = array();
	}

	public function testSettingsAndLogViewsNeedTheAdminPermission()
	{
		if (!defined('JPATH_COMPONENT'))
		{
			// the base class of Joomla's views still needs it
			define('JPATH_COMPONENT', JPATH_ADMINISTRATOR.'/components/com_bfstop');
		}
		$app = Factory::getApplication();
		$original = $app->getIdentity();
		$guest = new \Joomla\CMS\User\User();
		$app->loadIdentity($guest);
		try
		{
			foreach (array(\Codeling\Component\Bfstop\Administrator\View\Settings\HtmlView::class,
				\Codeling\Component\Bfstop\Administrator\View\Log\HtmlView::class) as $class)
			{
				$view = new $class();
				try
				{
					$view->display();
					$this->fail($class.' was shown to a user without permission');
				}
				catch (\Joomla\CMS\Access\Exception\NotAllowed $e)
				{
					$this->assertSame(403, $e->getCode());
				}
			}
		}
		finally
		{
			$app->loadIdentity($original);
		}
	}

	public function testUnsavedSettingsAreWhatTheSettingsPageShows()
	{
		// the plugin is enabled by the installation: until the settings are
		// saved it must behave like the page says
		$xml = simplexml_load_file(getenv('COM_BFSTOP_ROOT').'/admin/forms/settings.xml');
		foreach (\Codeling\Plugin\System\Bfstop\Extension\Bfstop::DefaultSettings as $name => $default)
		{
			$field = $xml->xpath('//field[@name="'.$name.'"]');
			$this->assertCount(1, $field, $name);
			$this->assertSame((string) $default, (string) $field[0]['default'], $name);
		}
	}

	public function testEditViewsRegisterTheirStylesheetsAsRealFiles()
	{
		// a path with a leading slash would become "//administrator/...", a link to another host
		foreach (array('Allow' => 'block', 'Block' => 'block', 'Htblock' => 'htblock') as $view => $folder)
		{
			$source = file_get_contents(getenv('COM_BFSTOP_ROOT').'/admin/src/View/'.$view.'/HtmlView.php');
			$this->assertSame(1, preg_match("#registerAndUseStyle\(\s*'([\w.]+)',\s*'([^']+)'\)#", $source, $m), $view);
			$this->assertFileExists(getenv('COM_BFSTOP_ROOT').'/admin/'.substr($m[2], strlen('administrator/components/com_bfstop/')), $view);
			$wa = new \Joomla\CMS\WebAsset\WebAssetManager(new \Joomla\CMS\WebAsset\WebAssetRegistry());
			$wa->registerAndUseStyle($m[1], $m[2]);
			$uri = $wa->getAsset('style', $m[1])->getUri();
			$this->assertStringStartsWith('/administrator/components/com_bfstop/tmpl/', $uri, $view);
			$this->assertStringEndsWith('/edit.css', $uri, $view);
		}
	}
}
