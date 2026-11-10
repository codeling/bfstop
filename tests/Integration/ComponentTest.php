<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Component\Bfstop\Administrator\Controller\DisplayController;
use Codeling\Component\Bfstop\Administrator\Helper\DurationHelper;
use Codeling\Component\Bfstop\Administrator\Helper\IpValidateHelper;
use Codeling\Component\Bfstop\Administrator\Helper\UnblockHelper;
use Codeling\Component\Bfstop\Administrator\Model\AllowModel;
use Codeling\Component\Bfstop\Administrator\Model\AllowlistModel;
use Codeling\Component\Bfstop\Administrator\Model\BlockModel;
use Codeling\Component\Bfstop\Administrator\Model\BlocklistModel;
use Codeling\Component\Bfstop\Administrator\Model\FailedloginlistModel;
use Codeling\Component\Bfstop\Administrator\Model\HtblocklistModel;
use Codeling\Component\Bfstop\Administrator\Model\SettingsModel;
use Codeling\Component\Bfstop\Administrator\Model\UsernamestatsModel;
use Codeling\Component\Bfstop\Site\Model\TokenunblockModel;
use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Codeling\Plugin\System\Bfstop\Helper\HtaccessHelper;
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

	public function testTokenOfABlockThatIsGoneUnblocksNothing()
	{
		// without the block, there is no address to bind the token to: it
		// must not unblock from wherever it is used
		$blockId = $this->insert('#__bfstop_bannedip', array('ipaddress' => '203.0.113.5', 'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		$this->insert('#__bfstop_unblock_token', array('token' => 'orphan', 'block_id' => $blockId, 'crdate' => self::minutesAgo(1)));
		$this->db->setQuery('DELETE FROM #__bfstop_bannedip WHERE id='.(int) $blockId);
		$this->db->execute();
		$model = $this->model(TokenunblockModel::class);
		$this->assertSame(TokenunblockModel::ResultNotFound, $model->process('orphan', true, '198.51.100.9', $this->logger));
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock'));
		$this->logger->errors = array(); // expected: "no block found"
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
		// a part to be active for has to be ticked
		$valid = array('enabledForOrigin' => array('1', '4'));
		$form = $this->settingsForm();
		$this->assertTrue($form->validate(array('params' => $valid + array('blockMode' => 'htaccess', 'blockNumber' => '10',
			'delayDuration' => '20', 'emailaddress' => 'a@example.org; b@example.org'))));
		foreach (array(array('blockMode', 'everything'), array('delayDuration', '100000'), array('blockNumber', '-3'),
			array('ipv6PrefixLength', '0'), array('unknownUsernameMode', 'x'), array('maxBlocksBefore', '7'),
			array('enabledForOrigin', array('3')), array('enabledForOrigin', '')) as list($name, $value))
		{
			$this->assertFalse($this->settingsForm()->validate(array('params' => array($name => $value) + $valid)),
				"$name=".json_encode($value));
		}
		$this->assertFalse($this->settingsForm()->validate(array('params' => array('blockNumber' => '10'))),
			'no part ticked');
	}

	public function testActiveForIsStoredAsABitmask()
	{
		// the form has a checkbox per part, the plugin reads (and 1.x stored)
		// their sum
		$this->assertSame(array('enabledForOrigin' => array('1', '4')),
			SettingsModel::paramsForForm(array('enabledForOrigin' => 5)));
		$this->assertSame(array('enabledForOrigin' => array('2')),
			SettingsModel::paramsForForm(array('enabledForOrigin' => '2')));
		$this->assertSame(array('blockNumber' => 7, 'enabledForOrigin' => array('1', '2', '4')),
			SettingsModel::paramsForForm(array('blockNumber' => 7)), 'never saved: the default');
		$this->assertSame(array('enabledForOrigin' => 5),
			SettingsModel::paramsForStorage(array('enabledForOrigin' => array('4', '1'))));
		$this->assertSame(array('blockNumber' => 7), SettingsModel::paramsForStorage(array('blockNumber' => 7)));
		// never active for nothing: without a part, the plugin's default applies
		$this->assertSame(array(), SettingsModel::paramsForStorage(array('enabledForOrigin' => array())));
		$this->assertSame(array(), SettingsModel::paramsForStorage(array('enabledForOrigin' => array('8'))));
		// and the form ticks the parts of the stored bitmask
		$form = $this->settingsForm();
		$form->bind(array('params' => SettingsModel::paramsForForm(array('enabledForOrigin' => 5))));
		$html = $form->getInput('enabledForOrigin', 'params');
		$this->assertSame(3, preg_match_all('/<input type="checkbox"/', $html), $html);
		$this->assertSame(array('1', '4'), preg_match_all('/<input type="checkbox"[^>]*value="(\d)"[^>]*checked/', $html, $m) ? $m[1] : array(), $html);

		$original = $this->getPluginParams();
		try
		{
			$this->setPluginParams(json_encode(array('enabledForOrigin' => 3)));
			$model = $this->model(SettingsModel::class);
			$model->getState();
			$formData = (new \ReflectionMethod($model, 'loadFormData'))->invoke($model);
			$this->assertSame(array('1', '2'), $formData->params['enabledForOrigin']);
			$this->assertTrue($model->save(array('params' => array('enabledForOrigin' => array('2', '4')))),
				implode(', ', $model->getErrors()));
			$this->assertSame(6, json_decode($this->getPluginParams(), true)['enabledForOrigin']);
		}
		finally
		{
			$this->setPluginParams($original);
		}
	}

	public function testEveryListAndIntegerSettingIsValidatedAgainstItsOptions()
	{
		$xml = simplexml_load_file(getenv('COM_BFSTOP_ROOT').'/admin/forms/settings.xml');
		$fields = $xml->xpath('//field[@type="list" or @type="integer" or @type="checkboxes"]');
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

	public function testUnblockingSeveralBlocksSkipsThoseAlreadyLifted()
	{
		$ids = array();
		foreach (array('203.0.113.70', '203.0.113.71', '203.0.113.72') as $ip)
		{
			$ids[] = $this->insert('#__bfstop_bannedip', array('ipaddress' => $ip, 'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		}
		$this->insert('#__bfstop_unblock', array('block_id' => $ids[0], 'source' => 0, 'crdate' => self::minutesAgo(5)));
		// the one which was lifted already used to end the loop: the others
		// selected with it stayed blocked
		$this->assertTrue(UnblockHelper::unblockDB($this->db, $ids, 0, $this->logger));
		$helper = new DatabaseHelper($this->logger);
		$this->assertFalse($helper->isIPBlocked('203.0.113.71'));
		$this->assertFalse($helper->isIPBlocked('203.0.113.72'));
		$this->assertSame(3, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock'));
	}

	public function testUnblockingTakesTheAddressOutOfTheHtaccessFile()
	{
		// the web server rejects an address as long as it is in the file - not
		// until the plugin's next maintenance, up to a day later
		$dir = sys_get_temp_dir().'/bfstop-unblock-'.bin2hex(random_bytes(4));
		mkdir($dir);
		$params = $this->getPluginParams();
		try
		{
			$this->setPluginParams(json_encode(array('blockMode' => 'htaccess', 'htaccessPath' => $dir)));
			$block = function ($ip)
			{
				return $this->insert('#__bfstop_bannedip', array('ipaddress' => $ip, 'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
			};
			$byBackend = $block('203.0.113.60');
			$block('203.0.113.61');
			$byToken = $block('203.0.113.62');
			$this->insert('#__bfstop_unblock_token', array('token' => 'valid', 'block_id' => $byToken, 'crdate' => self::minutesAgo(1)));
			$htaccess = new HtaccessHelper($dir, $this->logger);
			foreach (array('203.0.113.60', '203.0.113.61', '203.0.113.62', '203.0.113.63') as $ip)
			{
				$htaccess->denyIP($ip);              // .63: added by hand, no block in the database
			}

			$this->model(BlocklistModel::class)->unblock(array($byBackend), $this->logger);
			$this->assertSame(array('203.0.113.61', '203.0.113.62', '203.0.113.63'), $htaccess->getDeniedIPs());

			$this->assertSame(TokenunblockModel::ResultUnblocked,
				$this->model(TokenunblockModel::class)->process('valid', true, '203.0.113.62', $this->logger));
			$this->assertSame(array('203.0.113.61', '203.0.113.63'), $htaccess->getDeniedIPs());
		}
		finally
		{
			$this->setPluginParams($params);
			@unlink($dir.'/.htaccess');
			@rmdir($dir);
		}
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

	public function testSavingTheSettingsKeepsWhatThePluginStoresForItself()
	{
		// the form only has the settings; the plugin's own values must survive
		// a save, or it would e.g. convert all stored addresses again
		$original = $this->getPluginParams();
		try
		{
			$this->setPluginParams(json_encode(array('blockNumber' => 7, 'lastPurge' => 1700000000,
				'addressesCanonical' => 1)));
			$model = $this->model(SettingsModel::class);
			$model->getState();
			$this->assertTrue($model->save(array('params' => array('blockNumber' => 8, 'logLevel' => 8))),
				implode(', ', $model->getErrors()));
			$saved = json_decode($this->getPluginParams(), true);
			$this->assertSame(8, (int) $saved['blockNumber']);
			$this->assertSame(1700000000, $saved['lastPurge']);
			$this->assertSame(1, $saved['addressesCanonical']);
			$this->assertSame(\Codeling\Plugin\System\Bfstop\Extension\Bfstop::InternalSettings,
				array_values(array_intersect(array_keys($saved), \Codeling\Plugin\System\Bfstop\Extension\Bfstop::InternalSettings)));
			// a value given in the data wins (not that the form has them)
			$this->assertSame(array('lastPurge' => 5), SettingsModel::keepInternalSettings(array('lastPurge' => 5),
				array('lastPurge' => 1700000000)));
		}
		finally
		{
			$this->setPluginParams($original);
		}
	}

	public function testInstallerScriptHintAndVersionCheck()
	{
		require_once getenv('COM_BFSTOP_ROOT').'/installscript.php';
		$app = \Joomla\CMS\Factory::getApplication();
		$adapter = $this->createMock(\Joomla\CMS\Installer\InstallerAdapter::class);
		$adapter->method('getName')->willReturn('com_bfstop');
		$adapter->method('getManifest')->willReturn(simplexml_load_file(getenv('COM_BFSTOP_ROOT').'/bfstop.xml'));
		$script = new \com_bfstopInstallerScript($adapter);
		$app->getMessageQueue(true);

		// the hint about the settings is for new installations; on an update,
		// the plugin's script says what to look at, if anything
		$script->postflight('update', $adapter);
		$this->assertSame(array(), $app->getMessageQueue(true));
		$script->postflight('install', $adapter);
		$this->assertCount(1, $app->getMessageQueue(true));

		$cache = $this->queryValue("SELECT manifest_cache FROM #__extensions WHERE type='component' AND element='com_bfstop'");
		try
		{
			$this->assertTrue($script->preflight('update', $adapter));
			$newer = json_decode((string) $cache, true) ?: array();
			$newer['version'] = '99.0.0';
			$this->db->setQuery('UPDATE #__extensions SET manifest_cache='.$this->db->quote(json_encode($newer)).
				" WHERE type='component' AND element='com_bfstop'");
			$this->db->execute();
			$this->assertFalse($script->preflight('update', $adapter), 'replaced a newer version');
		}
		finally
		{
			$this->db->setQuery('UPDATE #__extensions SET manifest_cache='.$this->db->quote($cache).
				" WHERE type='component' AND element='com_bfstop'");
			$this->db->execute();
			$app->getMessageQueue(true);
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
			if ($name === 'enabledForOrigin')
			{
				// checkboxes, stored as a bitmask
				$this->assertSame($default, \Codeling\Plugin\System\Bfstop\Extension\Bfstop::originMask(
					explode(',', (string) $field[0]['default'])), $name);
				continue;
			}
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

	public function testEntriesOfTheEditFormsAreStoredInCanonicalForm()
	{
		$blockId = $this->saveNew(BlockModel::class,
			array('ipaddress' => '203.0.113.77/24', 'crdate' => '2026-01-02', 'duration' => '0'));
		$allowId = $this->saveNew(AllowModel::class, array('ipaddress' => '2001:DB8::ABCD', 'notes' => ''));
		$this->assertSame('203.0.113.0/24', $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip WHERE id='.$blockId));
		$this->assertSame('2001:db8::abcd', $this->queryValue('SELECT ipaddress FROM #__bfstop_allowlist WHERE id='.$allowId));
		$helper = new DatabaseHelper($this->logger);
		$this->assertTrue($helper->isIPBlocked('203.0.113.200'));
		$this->assertTrue($helper->isIPOnAllowList('2001:db8::ABCD'));
	}

	public function testBlockDurationsAreShownAsText()
	{
		Factory::getApplication()->getLanguage()->load('com_bfstop', getenv('COM_BFSTOP_ROOT').'/admin', 'en-GB', true);
		$this->assertSame('unlimited', DurationHelper::toReadable(0));
		$this->assertSame('15 minutes', DurationHelper::toReadable('15'));
		$this->assertSame('1 day', DurationHelper::toReadable(1440));
		// the settings' week and 30 days, and what the progressive block
		// duration makes of the others, used to show as language keys
		$this->assertSame('7 days', DurationHelper::toReadable(10080));
		$this->assertSame('30 days', DurationHelper::toReadable(43200));
		$this->assertSame('16 hours', DurationHelper::toReadable(960));
		$this->assertSame('20 minutes', DurationHelper::toReadable(20));
		$this->assertSame('90 minutes', DurationHelper::toReadable(90));
		$xml = simplexml_load_file(getenv('COM_BFSTOP_ROOT').'/admin/forms/settings.xml');
		$options = $xml->xpath('//field[@name="blockDuration"]/option');
		$this->assertNotEmpty($options);
		foreach ($options as $option)
		{
			// the progressive block duration doubles it up to 2^6 times
			for ($multiplier = 1; $multiplier <= 64; $multiplier *= 2)
			{
				$text = DurationHelper::toReadable(((int) $option['value']) * $multiplier);
				$this->assertStringNotContainsString('COM_BFSTOP_', $text);
			}
		}
	}

	public function testFailedLoginListNamesTheOrigins()
	{
		$view = (new \ReflectionClass(\Codeling\Component\Bfstop\Administrator\View\Failedloginlist\HtmlView::class))
			->newInstanceWithoutConstructor();
		$this->assertSame('Frontend', $view->getOriginName(0));
		$this->assertSame('Backend', $view->getOriginName('1'));
		$this->assertSame('API', $view->getOriginName(3));
	}

	public function testListOrderingIsAnIdentifierFromTheFilterFields()
	{
		$clause = fn ($column, $direction) => \Codeling\Component\Bfstop\Administrator\Helper\OrderingHelper::clause(
			$this->db, $column, $direction, array('a.id', 'a.ipaddress'), 'a.id', 'ASC');
		$this->assertSame($this->db->quoteName('a.ipaddress').' DESC', $clause('a.ipaddress', 'desc'));
		$this->assertSame($this->db->quoteName('a.id').' ASC', $clause('a.notes', 'DESC; DROP TABLE x'));
		$this->assertSame($this->db->quoteName('a.id').' ASC', $clause('(SELECT 1)', null));
		$this->assertSame($this->db->quoteName('a.id').' DESC', $clause(null, 'DESC'));
		// every list can still be sorted by every column it offers
		foreach (array(AllowlistModel::class, BlocklistModel::class, FailedloginlistModel::class, UsernamestatsModel::class) as $class)
		{
			$model = $this->model($class);
			$model->getState(); // populate the state now, so it doesn't overwrite what is set here
			foreach ((new \ReflectionProperty($class, 'filter_fields'))->getValue($model) as $column)
			{
				foreach (array('ASC', 'DESC') as $direction)
				{
					$model->setState('list.ordering', $column);
					$model->setState('list.direction', $direction);
					$query = (new \ReflectionMethod($model, 'getListQuery'))->invoke($model);
					$this->db->setQuery($query);
					$this->assertIsArray($this->db->loadObjectList(), "$class $column $direction");
					$this->assertStringContainsString($this->db->quoteName($column).' '.$direction, (string) $query);
				}
			}
		}
	}

	public function testListsAreSortableByTheirColumnHeaders()
	{
		// a column a header sorts by which isn't among the model's filter
		// fields is replaced by the default ordering: the header does nothing
		$models = array('allowlist' => AllowlistModel::class, 'blocklist' => BlocklistModel::class,
			'failedloginlist' => FailedloginlistModel::class, 'htblocklist' => HtblocklistModel::class,
			'usernamestats' => UsernamestatsModel::class);
		foreach ($models as $view => $class)
		{
			$head = file_get_contents(getenv('COM_BFSTOP_ROOT').'/admin/tmpl/'.$view.'/default_head.php');
			preg_match_all("#'grid\.sort',\s*'\w+',\s*'([^']+)'#", $head, $m);
			$this->assertNotEmpty($m[1], $view);
			$filterFields = (new \ReflectionProperty($class, 'filter_fields'))->getValue($this->model($class));
			foreach ($m[1] as $column)
			{
				$this->assertContains($column, $filterFields, "$view: column $column");
			}
		}
	}

	/**
	 * Runs $test with the given $live_site of the site, and puts it back.
	 */
	private function withLiveSite($liveSite, callable $test)
	{
		$app = Factory::getApplication();
		$original = $app->get('live_site', '');
		$app->set('live_site', $liveSite);
		try
		{
			return $test();
		}
		finally
		{
			$app->set('live_site', $original);
		}
	}

	public function testUnblockLinksNeedTheLiveSite()
	{
		// without $live_site, the link would have the host the attacker's
		// request named, see Bfstop::effectiveNotifyBlockedUser()
		Factory::getLanguage()->load('com_bfstop', getenv('COM_BFSTOP_ROOT').'/admin');
		$data = array('params' => array('enabledForOrigin' => array('1'), 'notifyBlockedUser' => '2'));
		$validate = function () use (&$data)
		{
			$model = $this->model(SettingsModel::class);
			return array($model->validate($this->settingsForm(), $data), $model->getErrors());
		};
		list($valid, $errors) = $this->withLiveSite('', $validate);
		$this->assertFalse($valid);
		$this->assertStringContainsString('$live_site', implode(' ', $errors));
		list($valid) = $this->withLiveSite('https://www.example.org', $validate);
		$this->assertIsArray($valid);
		$this->assertSame('2', $valid['params']['notifyBlockedUser']);
		// also links only for known addresses: others may share the address
		$data['params']['notifyBlockedUser'] = '1';
		list($valid) = $this->withLiveSite('', $validate);
		$this->assertFalse($valid, 'mode 1');
		$data['params']['notifyBlockedUser'] = '0';
		list($valid) = $this->withLiveSite('', $validate);
		$this->assertIsArray($valid, 'mode 0');
	}

	public function testSettingsPageProposesTheLiveSite()
	{
		Factory::getLanguage()->load('com_bfstop', getenv('COM_BFSTOP_ROOT').'/admin');
		$note = \Codeling\Component\Bfstop\Administrator\View\Settings\HtmlView::liveSiteNote();
		$root = rtrim(\Joomla\CMS\Uri\Uri::root(), '/');
		$this->assertStringContainsString('<code>public $live_site = &#039;'.htmlspecialchars($root, ENT_QUOTES, 'UTF-8').'&#039;;</code>', $note);
	}

	public function testWarnsIfUnblockLinksLackTheLiveSite()
	{
		$original = $this->getPluginParams();
		$app = Factory::getApplication();
		$warnings = function ($mode, $liveSite) use ($app)
		{
			$this->setPluginParams(json_encode(array('notifyBlockedUser' => $mode)));
			return $this->withLiveSite($liveSite, function () use ($app)
			{
				$app->getMessageQueue(true);
				$controller = new DisplayController(array('base_path' => JPATH_ADMINISTRATOR.'/components/com_bfstop'),
					new MVCFactory('Codeling\\Component\\Bfstop'), $app, $app->getInput());
				$controller->warnIfUnblockLinksNeedLiveSite();
				return count($app->getMessageQueue(true));
			});
		};
		try
		{
			$this->assertSame(1, $warnings(2, ''));
			$this->assertSame(0, $warnings(2, 'https://www.example.org'));
			$this->assertSame(1, $warnings(1, ''));
			$this->assertSame(0, $warnings(1, 'https://www.example.org'));
			$this->assertSame(0, $warnings(0, ''));
		}
		finally
		{
			$this->setPluginParams($original);
		}
	}

	/**
	 * A user who has exactly the given permissions in com_bfstop.
	 */
	private static function userWith(array $actions)
	{
		return new class ($actions) extends \Joomla\CMS\User\User
		{
			private $actions;

			public function __construct(array $actions)
			{
				parent::__construct();
				$this->actions = $actions;
			}

			public function authorise($action, $assetname = null)
			{
				return $assetname === 'com_bfstop' && in_array($action, $this->actions, true);
			}
		};
	}

	public function testOnlyWhoMayReadTheLogMayClearIt()
	{
		// the log view needs core.admin: who may only delete entries of the
		// lists must not be able to erase the log
		$app = Factory::getApplication();
		$original = $app->getIdentity();
		$input = $app->getInput();
		$input->post->set(\Joomla\CMS\Session\Session::getFormToken(), '1');
		$logFile = \Codeling\Plugin\System\Bfstop\Helper\LoggerHelper::getLogFiles()[0];
		$clear = function (array $actions) use ($app, $input, $logFile)
		{
			file_put_contents($logFile, "#<?php die('Forbidden.'); ?>\n2026-01-01T00:00:00+00:00 INFO an entry\n");
			$app->loadIdentity(self::userWith($actions));
			$controller = new \Codeling\Component\Bfstop\Administrator\Controller\LogController(
				array('base_path' => JPATH_ADMINISTRATOR.'/components/com_bfstop'), new MVCFactory('Codeling\\Component\\Bfstop'), $app, $input);
			$controller->clear();
			clearstatcache();
			return !(is_file($logFile) && str_contains((string) file_get_contents($logFile), 'an entry'));
		};
		try
		{
			$this->assertFalse($clear(array('core.manage', 'core.delete')), 'core.delete alone');
			$this->assertFalse($clear(array('core.manage', 'core.admin')), 'core.admin alone');
			$this->assertTrue($clear(array('core.manage', 'core.admin', 'core.delete')));
		}
		finally
		{
			$app->loadIdentity($original);
			@unlink($logFile);
		}
	}

	public function testChangingTheAllowListNeedsTheAdminPermission()
	{
		// an entry exempts addresses from all protection: like the settings,
		// it needs core.admin, not only core.create / core.edit
		$app = Factory::getApplication();
		$original = $app->getIdentity();
		$controller = new \Codeling\Component\Bfstop\Administrator\Controller\AllowController(
			array('base_path' => JPATH_ADMINISTRATOR.'/components/com_bfstop', 'option' => 'com_bfstop'),
			new MVCFactory('Codeling\\Component\\Bfstop'), $app, $app->getInput());
		$allowAdd = new \ReflectionMethod($controller, 'allowAdd');
		$allowEdit = new \ReflectionMethod($controller, 'allowEdit');
		try
		{
			$app->loadIdentity(self::userWith(array('core.manage', 'core.create', 'core.edit')));
			$this->assertFalse($allowAdd->invoke($controller, array()));
			$this->assertFalse($allowEdit->invoke($controller, array('id' => 1), 'id'));
			$app->loadIdentity(self::userWith(array('core.manage', 'core.admin')));
			$this->assertFalse($allowAdd->invoke($controller, array()), 'core.create is still needed');
			$app->loadIdentity(self::userWith(array('core.manage', 'core.admin', 'core.create', 'core.edit')));
			$this->assertTrue($allowAdd->invoke($controller, array()));
			$this->assertTrue($allowEdit->invoke($controller, array('id' => 1), 'id'));
		}
		finally
		{
			$app->loadIdentity($original);
		}
	}

	/**
	 * Saves the backend's ".htaccess block" form with $ipaddress, as a user
	 * with $actions; returns the addresses in the file afterwards.
	 */
	private function saveHtaccessBlock($dir, $ipaddress, array $actions)
	{
		$app = Factory::getApplication();
		$original = $app->getIdentity();
		$input = $app->getInput();
		$input->post->set(\Joomla\CMS\Session\Session::getFormToken(), '1');
		$input->post->set('jform', array('ipaddress' => $ipaddress));
		try
		{
			$app->loadIdentity(self::userWith($actions));
			$controller = new \Codeling\Component\Bfstop\Administrator\Controller\HtblockController(
				array('base_path' => JPATH_ADMINISTRATOR.'/components/com_bfstop', 'option' => 'com_bfstop'),
				new MVCFactory('Codeling\\Component\\Bfstop'), $app, $input);
			$controller->save();
			$app->getMessageQueue(true);
			return (new HtaccessHelper($dir, null))->getDeniedIPs();
		}
		finally
		{
			$app->loadIdentity($original);
			$input->post->set('jform', null);
		}
	}

	public function testHtaccessBlockFormRefusesNetworksWithAllowedAddresses()
	{
		// the web server knows nothing of the allow list: a network in the
		// .htaccess file would turn away the allowed addresses in it
		$dir = sys_get_temp_dir().'/bfstop-htblock-'.getmypid();
		mkdir($dir);
		$original = $this->getPluginParams();
		$actions = array('core.manage', 'core.create');
		try
		{
			$this->setPluginParams(json_encode(array('blockMode' => 'htaccess', 'htaccessPath' => $dir)));
			$this->insert('#__bfstop_allowlist', array('ipaddress' => '203.0.113.7', 'notes' => ''));
			$this->insert('#__bfstop_allowlist', array('ipaddress' => '198.51.100.0/24', 'notes' => ''));
			$this->assertSame(array(), $this->saveHtaccessBlock($dir, '203.0.113.0/24', $actions), 'contains an allowed address');
			$this->assertSame(array(), $this->saveHtaccessBlock($dir, '198.51.100.9', $actions), 'in an allowed network');
			$this->assertSame(array('192.0.2.0/24'), $this->saveHtaccessBlock($dir, '192.0.2.0/24', $actions));
		}
		finally
		{
			$this->setPluginParams($original);
			@unlink($dir.'/.htaccess');
			@rmdir($dir);
		}
	}
}
