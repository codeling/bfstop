<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Origin;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Repository\UnblockTokenRepository;
use Codeling\Plugin\System\Bfstop\Service\Responder;
use Joomla\CMS\Factory;

/**
 * How the plugin treats requests from a blocked IP address, depending on its
 * settings: each request runs in a separate process (see fixtures/request.php),
 * which reads the plugin's settings from the database as a real request does.
 */
class BlockedRequestTest extends IntegrationTestCase
{
	private const BlockedMessage = 'BFSTOP TEST: blocked';
	private const Ip = '203.0.113.41';

	private static $originalParams;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
		$db->setQuery("SELECT params FROM #__extensions WHERE type='component' AND element='com_bfstop'");
		self::$originalParams = $db->loadResult();
	}

	public static function tearDownAfterClass(): void
	{
		if (self::$originalParams !== null)
		{
			$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
			self::storeSettings($db, self::$originalParams);
		}
	}

	private function configure(array $params = array())
	{
		$this->setSettings(json_encode($params + array(
			'blockMode' => 'full',
			'blockedMessage' => self::BlockedMessage,
			'logLevel' => 8, // errors only
		)));
	}

	private function block($ip = self::Ip, $minutesAgo = 0, $duration = 60)
	{
		return $this->insert('#__bfstop_bannedip', array('ipaddress' => $ip,
			'crdate' => self::minutesAgo($minutesAgo), 'duration' => $duration), 'id');
	}

	/**
	 * @param string|null $backendUser null for a request to the site, else one
	 *                                 to the backend: '' by a guest, or by the
	 *                                 user with this username
	 * @param string[]    $options     further options of fixtures/request.php
	 *                                 (--api, --server=...)
	 */
	private function request($query = '', $ip = self::Ip, $routed = true, $backendUser = null, array $options = array())
	{
		if ($backendUser !== null)
		{
			$options[] = '--admin'.($backendUser === '' ? '' : '='.$backendUser);
		}
		if (!$routed)
		{
			$options[] = '--no-route';
		}
		$command = escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/fixtures/request.php').' '.
			escapeshellarg($ip).' '.escapeshellarg($query).
			implode('', array_map(function ($option) { return ' '.escapeshellarg($option); }, $options)).
			' 2>&1';
		exec($command, $output, $exitCode);
		$output = implode("\n", $output);
		$this->assertSame(0, $exitCode, $output);
		return $output;
	}

	private function assertBlocked($query = '', $ip = self::Ip, $backendUser = null)
	{
		$output = $this->request($query, $ip, true, $backendUser);
		$this->assertStringContainsString(self::BlockedMessage, $output, "request '$query' should be blocked");
		$this->assertStringNotContainsString('NOT BLOCKED', $output);
	}

	private function assertNotBlocked($query = '', $ip = self::Ip, $backendUser = null)
	{
		$output = $this->request($query, $ip, true, $backendUser);
		$this->assertStringContainsString('NOT BLOCKED', $output, "request '$query' should not be blocked");
		$this->assertStringNotContainsString(self::BlockedMessage, $output);
	}

	/**
	 * A request to the Web Services API; $headers as in $_SERVER
	 * ('HTTP_AUTHORIZATION' => 'Bearer ...')
	 */
	private function apiRequest($ip = self::Ip, array $headers = array())
	{
		$options = array('--api');
		foreach ($headers as $name => $value)
		{
			$options[] = '--server='.$name.'='.$value;
		}
		return $this->request('', $ip, true, null, $options);
	}

	public function testFullModeBlocksEverything()
	{
		$this->configure();
		$this->block();
		$this->assertBlocked();
		$this->assertBlocked('option=com_content&view=article&id=1');
		$this->assertBlocked('option=com_users&task=user.login');
		$this->assertNotBlocked('', '203.0.113.42');
	}

	public function testBlockIsEnforcedOnlyAfterRouting()
	{
		// with SEF URLs option/view are empty until the router ran, so the
		// password recovery exemption can only be evaluated afterwards
		$this->configure();
		$this->block();
		$output = $this->request('', self::Ip, false);
		$this->assertStringContainsString('NOT BLOCKED', $output);
		$this->assertBlocked();
	}

	public function testBackendAndApiAreRefusedBeforeRouting()
	{
		// no exemption of a blocked client is a page of the backend or the
		// API: "Full Site" refuses them already in onAfterInitialise
		$this->configure();
		$this->block();
		$output = $this->request('', self::Ip, false, '');
		$this->assertStringContainsString(self::BlockedMessage, $output, 'backend');
		$output = $this->request('', self::Ip, false, null, array('--api'));
		$this->assertStringNotContainsString('NOT BLOCKED', $output, 'API');
		$this->assertStringContainsString('"errors"', $output, 'API');
		$this->assertStringContainsString('NOT BLOCKED', $this->request('', '203.0.113.42', false, ''), 'not blocked');
		// the site waits for the router (see testBlockIsEnforcedOnlyAfterRouting),
		// and so does "Login Only", which has to know whether it is a login
		$this->configure(array('blockMode' => 'loginonly'));
		$this->assertStringContainsString('NOT BLOCKED', $this->request('', self::Ip, false, ''), 'Login Only');
		$this->assertStringContainsString('NOT BLOCKED',
			$this->request('option=com_login&task=login', self::Ip, false, ''), 'Login Only, before routing');
		$this->assertBlocked('option=com_login&task=login', self::Ip, '');
	}

	private function knownIps()
	{
		$this->db->setQuery('SELECT ipaddress FROM #__bfstop_knownip ORDER BY ipaddress');
		return $this->db->loadColumn();
	}

	private function knownIp($ip, $daysAgo)
	{
		$this->insert('#__bfstop_knownip', array('ipaddress' => $ip, 'username' => 'bob',
			'first_success' => self::minutesAgo($daysAgo * 1440 + 1), 'last_success' => self::minutesAgo($daysAgo * 1440)));
	}

	public function testDailyMaintenancePrunesAndRemembersWhenItRan()
	{
		// purge age 0: nothing is purged by age, but this has to happen regardless
		$this->configure(array('deleteOld' => 0, 'blockNumber' => 7));
		$this->knownIp('203.0.113.1', 400);
		$this->knownIp('203.0.113.2', 1);
		// unblock tokens nobody can use any more
		$this->insert('#__bfstop_unblock_token', array('token' => str_repeat('ab', 20), 'block_id' => 1,
			'crdate' => self::minutesAgo(4 * 24 * 60)));
		$this->insert('#__bfstop_unblock_token', array('token' => str_repeat('cd', 20), 'block_id' => 2,
			'crdate' => self::minutesAgo(60)));
		// reverse-DNS results which have expired
		$this->insert('#__bfstop_dnscache', array('ipaddress' => '203.0.113.77', 'hostname' => null,
			'checked_at' => self::minutesAgo(8 * 24 * 60)));
		$this->insert('#__bfstop_dnscache', array('ipaddress' => '203.0.113.78', 'hostname' => null,
			'checked_at' => self::minutesAgo(60)));
		$this->assertNotBlocked();
		$this->assertSame(array('203.0.113.2'), $this->knownIps());
		$this->assertSame(array('203.0.113.78'), $this->db->setQuery('SELECT ipaddress FROM #__bfstop_dnscache')->loadColumn());
		$this->assertSame(array(UnblockTokenRepository::hash(str_repeat('cd', 20))), $this->db->setQuery('SELECT token FROM #__bfstop_unblock_token')->loadColumn());
		$this->assertGreaterThan(time() - 60, (int) $this->queryValue("SELECT value FROM #__bfstop_state WHERE name='lastMaintenance'"));
		$saved = json_decode($this->getSettings(), true);
		$this->assertArrayNotHasKey('lastPurge', $saved, 'the settings are not written for this any more');
		$this->assertSame(7, $saved['blockNumber'], 'the other settings are left alone');
	}

	public function testMaintenanceTakesLiftedBlocksOutOfTheHtaccessFile()
	{
		$dir = sys_get_temp_dir().'/bfstop-maintenance-'.bin2hex(random_bytes(4));
		mkdir($dir);
		try
		{
			$this->configure(array('blockMode' => 'htaccess', 'htaccessPath' => $dir));
			$this->block('203.0.113.50', 120, 60);   // ran out
			$this->block('203.0.113.51', 10, 60);    // still active
			$helper = new HtaccessHelper($dir, $this->logger);
			foreach (array('203.0.113.50', '203.0.113.51', '203.0.113.52') as $ip)
			{
				$helper->denyIP($ip);                // .52: added by hand, no block in the database
			}
			$this->assertNotBlocked();
			$this->assertSame(array('203.0.113.51', '203.0.113.52'), (new HtaccessHelper($dir, $this->logger))->getDeniedIPs());
		}
		finally
		{
			@unlink($dir.'/.htaccess');
			@rmdir($dir);
		}
	}

	/**
	 * The entries of the time the file blocked: with another blocking mode,
	 * nothing would take them out, also once their blocks are over.
	 */
	public function testMaintenanceTakesTheBlocksOutOfAnHtaccessFileWhichNoLongerBlocks()
	{
		$dir = sys_get_temp_dir().'/bfstop-maintenance-'.bin2hex(random_bytes(4));
		mkdir($dir);
		try
		{
			$this->configure(array('blockMode' => 'full', 'htaccessPath' => $dir));
			$this->block('203.0.113.50', 120, 60);   // ran out
			$this->block('203.0.113.51', 10, 60);    // still active: in the database
			$helper = new HtaccessHelper($dir, $this->logger);
			foreach (array('203.0.113.50', '203.0.113.51', '203.0.113.52') as $ip)
			{
				$helper->denyIP($ip);                // .52: added by hand, no block in the database
			}
			$this->assertNotBlocked();
			$this->assertSame(array('203.0.113.52'), (new HtaccessHelper($dir, $this->logger))->getDeniedIPs());
			$this->assertTrue((new Repositories($this->logger))->blocks()->isBlocked('203.0.113.51'));
		}
		finally
		{
			@unlink($dir.'/.htaccess');
			@rmdir($dir);
		}
	}

	public function testMaintenanceTakesBlocksOutOfTheHtaccessFileBeforeItPurgesThem()
	{
		// without the block in the database, the entry couldn't be told from
		// one added by hand any more, and would stay for good
		$dir = sys_get_temp_dir().'/bfstop-maintenance-'.bin2hex(random_bytes(4));
		mkdir($dir);
		try
		{
			$this->configure(array('blockMode' => 'htaccess', 'htaccessPath' => $dir, 'deleteOld' => 1));
			$this->block('203.0.113.53', 3 * 7 * 24 * 60, 60);   // ran out three weeks ago
			(new HtaccessHelper($dir, $this->logger))->denyIP('203.0.113.53');
			$this->assertNotBlocked();
			$this->assertSame(array(), (new HtaccessHelper($dir, $this->logger))->getDeniedIPs());
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'), 'purged');
		}
		finally
		{
			@unlink($dir.'/.htaccess');
			@rmdir($dir);
		}
	}

	public function testNoRequestRunsTheMaintenanceWhichRanAnHourAgo()
	{
		$this->configure();
		$this->markMaintenanceDone(time() - 3600);
		$this->knownIp('203.0.113.1', 400);
		$this->assertNotBlocked();
		$this->assertSame(array('203.0.113.1'), $this->knownIps(), 'ran an hour ago already');
	}

	public function testNoRequestRunsTheMaintenanceWhileTheTaskKeepsUpWithIt()
	{
		// the task runs every 24 hours: a request waits for two days
		$this->configure();
		$this->markMaintenanceDone(time() - 47 * 3600);
		$this->knownIp('203.0.113.1', 400);
		$this->assertNotBlocked();
		$this->assertSame(array('203.0.113.1'), $this->knownIps(), 'not overdue yet');
	}

	public function testARequestRunsTheMaintenanceTheTaskDidNot()
	{
		// no scheduler, or its task is gone or switched off
		$this->configure();
		$this->markMaintenanceDone(time() - 49 * 3600);
		$this->knownIp('203.0.113.1', 400);
		$this->assertNotBlocked();
		$this->assertSame(array(), $this->knownIps(), 'overdue: done by the request');
		$this->assertGreaterThan(time() - 60, (int) $this->queryValue("SELECT value FROM #__bfstop_state WHERE name='lastMaintenance'"));
		// and then not again
		$this->knownIp('203.0.113.1', 400);
		$this->assertNotBlocked();
		$this->assertSame(array('203.0.113.1'), $this->knownIps());
	}

	public function testBlockPageIsNeverCached()
	{
		$headers = Responder::blockedResponseHeaders();
		$this->assertContains('Cache-Control: no-store, no-cache, must-revalidate, private', $headers);
		$this->assertContains('Pragma: no-cache', $headers);
		// nor indexed, and what it is isn't left to the browser to guess
		$this->assertContains('X-Robots-Tag: noindex, nofollow', $headers);
		$this->assertContains('Content-Type: text/html; charset=utf-8', $headers);
		$this->assertContains('X-Content-Type-Options: nosniff', $headers);
		// and not shown in another site's frame
		$this->assertContains("Content-Security-Policy: frame-ancestors 'none'", $headers);
		$this->assertContains('X-Frame-Options: DENY', $headers);
		foreach ($headers as $header)
		{
			$this->assertStringStartsNotWith('HTTP/', $header, 'the status is set with http_response_code()');
		}
	}

	public function testBlockedResponseCode()
	{
		$this->assertSame(403, Responder::blockedResponseCode(true));
		$this->assertNull(Responder::blockedResponseCode(false));
	}

	public function testBlockPageIsAnErrorByDefault()
	{
		$this->configure();
		$this->block();
		$this->assertMatchesRegularExpression('/^STATUS: 403$/m', $this->request());
	}

	public function testErrorStatusCanBeSwitchedOff()
	{
		$this->configure(array('useHttpError' => 0));
		$this->block();
		$output = $this->request();
		$this->assertStringContainsString(self::BlockedMessage, $output);
		$this->assertDoesNotMatchRegularExpression('/^STATUS: 403$/m', $output);
	}

	public function testBlockedMessageCanShowIp()
	{
		$this->configure(array('blockedMsgShowIP' => 1));
		$this->block();
		$this->assertStringContainsString(self::Ip, $this->request());
	}

	public function testExpiredBlockNoLongerApplies()
	{
		$this->configure();
		$this->block(self::Ip, 61, 60);
		$this->assertNotBlocked();
	}

	public function testPermanentBlockNeverExpires()
	{
		$this->configure();
		// duration 0 = "forever"; 5 years is still within BlockRepository::UnlimitedDuration
		$this->block(self::Ip, 5 * 365 * 24 * 60, 0);
		$this->assertBlocked();
	}

	public function testLoginOnlyModeOnlyRejectsLoginAttempts()
	{
		$this->configure(array('blockMode' => 'loginonly'));
		$this->block();
		$this->assertNotBlocked();
		$this->assertNotBlocked('option=com_users&view=login');
		// frontend login form
		$this->assertBlocked('option=com_users&task=user.login');
		// backend login form
		$this->assertBlocked('option=com_login&task=login');
	}

	public function testLoginOnlyModeRecognisesEveryWayToLogIn()
	{
		// Joomla lowercases the method, ignores what follows a second dot and
		// takes the controller from its own parameter if the task has no dot:
		// each of these runs UserController::login()
		$this->configure(array('blockMode' => 'loginonly'));
		$this->block();
		$this->assertBlocked('option=com_users&task=user.LOGIN');
		$this->assertBlocked('option=com_users&task=User.Login');
		$this->assertBlocked('option=com_users&task=user.login.x');
		$this->assertBlocked('option=com_users&controller=user&task=login');
		$this->assertBlocked('option=com_users&task=LOGIN');
		$this->assertBlocked('option=com_login&task=LOGIN');
		// still no login
		$this->assertNotBlocked('option=com_users&task=user.logout');
		$this->assertNotBlocked('option=com_users&view=login&task=display');
		$this->assertNotBlocked('option=com_content&task=user.login');
	}

	public function testLoginOnlyModeRecognisesBackendLoginsWithoutComLogin()
	{
		// the backend runs com_login for every request of a guest, whatever
		// component it names (AdministratorApplication::findOption(), called
		// after onAfterRoute): each of these is a login
		$this->configure(array('blockMode' => 'loginonly'));
		$this->block();
		$this->assertBlocked('option=com_login&task=login', self::Ip, '');
		$this->assertBlocked('task=login', self::Ip, '');
		$this->assertBlocked('option=com_cpanel&task=login', self::Ip, '');
		$this->assertBlocked('option=com_users&task=login', self::Ip, '');
		$this->assertBlocked('option=com_content&task=display.login', self::Ip, '');
		// the login form itself stays reachable, as do the components the
		// backend lets a guest reach
		$this->assertNotBlocked('', self::Ip, '');
		$this->assertNotBlocked('option=com_cpanel', self::Ip, '');
		$this->assertNotBlocked('option=com_ajax&task=login', self::Ip, '');
		// a logged-in user's request goes where it says
		$this->assertNotBlocked('option=com_content&task=display.login', self::Ip, 'Admin');
		$this->assertBlocked('option=com_login&task=login', self::Ip, 'Admin');
	}

	public function testBlockedAddressIsRejectedByTheApi()
	{
		$this->configure();
		$this->block();
		$output = $this->apiRequest();
		$this->assertStringNotContainsString('NOT BLOCKED', $output);
		// in the form the API answers errors in, not a page
		$this->assertStringContainsString('{"errors":[{"title":"'.self::BlockedMessage.'","code":403}]}', $output);
		$this->assertStringContainsString('STATUS: 403', $output);
		$this->assertStringContainsString('NOT BLOCKED', $this->apiRequest('203.0.113.42'));
	}

	public function testApiIsOnlyProtectedIfSwitchedOn()
	{
		$this->configure(array('enabledForOrigin' => Origin::Frontend | Origin::Backend));
		$this->block();
		$this->assertStringContainsString('NOT BLOCKED', $this->apiRequest());
		$this->assertBlocked();
		$this->configure(array('enabledForOrigin' => Origin::Api));
		$this->assertStringNotContainsString('NOT BLOCKED', $this->apiRequest());
		$this->assertNotBlocked();
	}

	public function testUnsavedSettingsProtectTheApi()
	{
		$this->setSettings(json_encode(array('blockedMessage' => self::BlockedMessage, 'logLevel' => 8)));
		$this->block();
		$this->assertStringNotContainsString('NOT BLOCKED', $this->apiRequest());
	}

	public function testLoginOnlyModeRejectsApiRequestsWithCredentials()
	{
		// each API request with credentials is a login
		$this->configure(array('blockMode' => 'loginonly'));
		$this->block();
		$this->assertStringContainsString('NOT BLOCKED', $this->apiRequest());
		foreach (array(
			array('HTTP_AUTHORIZATION' => 'Bearer c2hhMjU2OjQyOmFiYw=='),
			array('HTTP_X_JOOMLA_TOKEN' => 'c2hhMjU2OjQyOmFiYw=='),
			array('HTTP_AUTHORIZATION' => 'Basic '.base64_encode('admin:secret')),
			array('PHP_AUTH_USER' => 'admin', 'PHP_AUTH_PW' => 'secret')) as $headers)
		{
			$output = $this->apiRequest(self::Ip, $headers);
			$this->assertStringNotContainsString('NOT BLOCKED', $output, implode(', ', array_keys($headers)));
			$this->assertStringContainsString(self::BlockedMessage, $output);
		}
	}

	public function testActiveForBitmask()
	{
		$this->assertSame(7, Origin::mask(7));
		$this->assertSame(5, Origin::mask(array('1', '4')));
		$this->assertSame(2, Origin::mask('2'));
		// bits of no part, and what isn't a number, are dropped
		$this->assertSame(1, Origin::mask(array('1', '8', 'x', null)));
		$this->assertSame(0, Origin::mask(''));
		$this->assertSame(array('1', '2', '4'), Origin::list(15));
		$this->assertSame(array('2', '4'), Origin::list('6'));
		$this->assertSame(array(), Origin::list(0));
	}

	public function testActiveForStoredAsAListIsUnderstood()
	{
		// what the plugin reads is a bitmask; a list of bits works as well
		$this->configure(array('enabledForOrigin' => array('4')));
		$this->block();
		$this->assertNotBlocked();
		$this->assertStringNotContainsString('NOT BLOCKED', $this->apiRequest());
	}

	public function testBlockedApiResponse()
	{
		$this->assertSame('{"errors":[{"title":"Blocked & gone","code":403}]}',
			Responder::blockedApiResponse('<b>Blocked</b> &amp; gone ', 403));
		$this->assertSame('{"errors":[{"title":"x"}]}', Responder::blockedApiResponse('x', null));
	}

	public function testUnblockTokenAndPasswordRecoveryAreNoPassToTheBackend()
	{
		// in the backend, these requests of a guest would go to com_login
		$this->configure();
		$id = $this->block();
		$token = (new Repositories($this->logger))->unblockTokens()->add($id, str_repeat('ef', 20));
		$this->assertNotBlocked('option=com_bfstop&view=tokenunblock&token='.$token);
		$this->assertBlocked('option=com_bfstop&view=tokenunblock&token='.$token, self::Ip, '');
		$this->assertNotBlocked('option=com_users&view=reset');
		$this->assertBlocked('option=com_users&view=reset', self::Ip, '');
		$this->assertBlocked('option=com_users&task=reset.request', self::Ip, '');
	}

	public function testPasswordRecoveryStaysReachable()
	{
		// a blocked legitimate user must still be able to reset their password
		$this->configure();
		$this->block();
		$this->assertNotBlocked('option=com_users&view=reset');
		$this->assertNotBlocked('option=com_users&view=remind');
		$this->assertNotBlocked('option=com_users&view=reset&layout=confirm');
		$this->assertNotBlocked('option=com_users&view=reset&layout=complete');
		$this->assertBlocked('option=com_users&view=login');
	}

	public function testPasswordRecoveryFormsCanBeSubmitted()
	{
		// the forms of the reset and remind views post a task, usually without
		// view=reset (index.php?task=reset.request): without these the blocked
		// user could see the form, but not get the mail
		$this->configure();
		$this->block();
		$this->assertNotBlocked('option=com_users&task=reset.request');
		$this->assertNotBlocked('option=com_users&task=reset.confirm');
		$this->assertNotBlocked('option=com_users&task=reset.complete');
		$this->assertNotBlocked('option=com_users&task=remind.remind');
		$this->assertNotBlocked('option=com_users&task=user.remind');
		$this->assertNotBlocked('option=com_users&view=reset&task=reset.request');
		// spelled the way Joomla's dispatcher understands it as well
		$this->assertNotBlocked('option=com_users&task=Reset.Request');
		$this->assertNotBlocked('option=com_users&controller=reset&task=request');
	}

	public function testPasswordRecoveryViewIsNoPassForOtherTasks()
	{
		// Joomla runs the task, not the view: with view=reset in the request,
		// a login (or anything else) must not get around the block
		$this->configure();
		$this->block();
		$this->assertBlocked('option=com_users&view=reset&task=user.login');
		$this->assertBlocked('option=com_users&view=remind&task=user.login');
		$this->assertBlocked('option=com_users&view=reset&task=login&controller=user');
		$this->assertBlocked('option=com_users&view=reset&task=user.LOGIN');
		$this->assertBlocked('option=com_users&view=reset&task=registration.register');
		$this->assertBlocked('option=com_users&view=reset&task[]=reset.request');
		// "remind" is only a recovery task of the remind and user controllers
		$this->assertBlocked('option=com_users&task=profile.remind');
		$this->assertBlocked('option=com_content&task=reset.request');
	}

	public function testValidUnblockTokenGetsThrough()
	{
		$this->configure();
		$blockId = $this->block();
		$token = (new Repositories($this->logger))->unblockTokens()->add($blockId, str_repeat('ab', 20));
		$this->assertNotBlocked('option=com_bfstop&view=tokenunblock&token='.$token);
		$this->assertBlocked('option=com_bfstop&view=tokenunblock&token='.str_repeat('0', 40));
		$this->assertBlocked('option=com_bfstop&view=tokenunblock');
	}

	public function testUnblockTokenIsNoPassForOtherRequests()
	{
		// the token is consumed by the unblock page only; as a parameter of
		// any other request (here: a login) it must not get around the block
		$this->configure();
		$blockId = $this->block();
		$token = (new Repositories($this->logger))->unblockTokens()->add($blockId, str_repeat('ab', 20));
		$this->assertBlocked('option=com_users&task=user.login&view=tokenunblock&token='.$token);
		$this->assertBlocked('option=com_content&view=tokenunblock&token='.$token);
		$this->assertBlocked('option=com_bfstop&task=display&view=tokenunblock&token='.$token);
		$this->assertNotBlocked('option=com_bfstop&view=tokenunblock&token='.$token);
	}

	public function testUnblockTokenOfAnotherBlockIsNoPass()
	{
		$this->configure();
		$this->block();
		$otherBlockId = $this->block('203.0.113.99');
		$token = (new Repositories($this->logger))->unblockTokens()->add($otherBlockId, str_repeat('cd', 20));
		$this->assertBlocked('option=com_bfstop&view=tokenunblock&token='.$token);
	}

	public function testExpiredUnblockTokenIsNoPass()
	{
		$this->configure();
		$blockId = $this->block();
		$this->insert('#__bfstop_unblock_token', array('token' => str_repeat('ef', 20),
			'block_id' => $blockId, 'crdate' => self::minutesAgo(4 * 24 * 60)));
		$this->assertBlocked('option=com_bfstop&view=tokenunblock&token='.str_repeat('ef', 20));
	}

	/**
	 * The pass a valid token gives is for the unblock view and nothing else:
	 * whatever else a request carries (another task or component, in any
	 * spelling - Joomla matches the task case-insensitively, and the backend
	 * decides on the component itself - or a token which isn't a plain
	 * string) must still be rejected. The one request which gets through is
	 * the unblock view itself.
	 */
	public function testUnblockTokenPassIsLimitedToTheUnblockView()
	{
		$this->configure();
		$blockId = $this->block();
		$token = (new Repositories($this->logger))->unblockTokens()->add($blockId, str_repeat('ab', 20));
		$this->assertBlocked('option=com_users&task=user.LOGIN&view=tokenunblock&token='.$token);
		$this->assertBlocked('option=com_login&task=login&view=tokenunblock&token='.$token);
		$this->assertBlocked('option=com_bfstop&task=user.login&view=tokenunblock&token='.$token);
		$this->assertBlocked('option=COM_BFSTOP&view=tokenunblock&token='.$token);
		$this->assertBlocked('option=com_bfstop&view=TOKENUNBLOCK&token='.$token);
		$this->assertBlocked('option=com_bfstop&view=tokenunblock&token[]='.$token);
		$this->assertNotBlocked('option=com_bfstop&view=tokenunblock&token='.$token);
	}

	/**
	 * A token is bound to the blocks it was issued for: a valid token of
	 * another address's block doesn't open the unblock view, whatever the
	 * request looks like otherwise.
	 */
	public function testUnblockTokenOfAnotherAddressIsNoPassForTheUnblockView()
	{
		$this->configure();
		$this->block();
		$otherBlockId = $this->block('203.0.113.99');
		$otherToken = (new Repositories($this->logger))->unblockTokens()->add($otherBlockId, str_repeat('cd', 20));
		$this->assertBlocked('option=com_bfstop&view=tokenunblock&token='.$otherToken);
	}

	/**
	 * Parameters given as arrays ("option[]=x") are no valid values: they must
	 * neither break the plugin nor get a request past the block.
	 */
	public function testArrayParametersDoNotBreakTheBlock()
	{
		$this->configure();
		$blockId = $this->block();
		$token = (new Repositories($this->logger))->unblockTokens()->add($blockId, str_repeat('ab', 20));
		$this->assertBlocked('option[]=com_bfstop&view=tokenunblock&token='.$token);
		$this->assertBlocked('option=com_bfstop&view[]=tokenunblock&token='.$token);
		$this->assertBlocked('option=com_bfstop&view=tokenunblock&task[]=display&token='.$token);
		$this->assertBlocked('option[]=com_users&view[]=reset');
		$this->assertBlocked('option[]=com_users&task[]=user.login');
	}

	public function testRejectedRequestsAreCounted()
	{
		$this->configure();
		$blockId = $this->block();
		$this->assertBlocked();
		$this->assertBlocked();
		$this->assertSame(2, (int) $this->queryValue('SELECT attempts FROM #__bfstop_bannedip WHERE id='.$blockId));
		$this->assertNotNull($this->queryValue('SELECT last_attempt FROM #__bfstop_bannedip WHERE id='.$blockId));
	}

	public function testUnblockedBlockNoLongerApplies()
	{
		$this->configure();
		$blockId = $this->block();
		$this->insert('#__bfstop_unblock', array('block_id' => $blockId, 'source' => 0, 'crdate' => self::minutesAgo(0)));
		$this->assertNotBlocked();
	}

	/**
	 * Renames the block table for $test, so that it can't be read.
	 */
	private function withoutBlockTable(callable $test)
	{
		$db = $this->db;
		$table = $db->getPrefix().'bfstop_bannedip';
		$rename = function ($from, $to) use ($db)
		{
			$db->setQuery($db->getServerType() === 'postgresql'
				? 'ALTER TABLE '.$db->quoteName($from).' RENAME TO '.$db->quoteName($to)
				: 'RENAME TABLE '.$db->quoteName($from).' TO '.$db->quoteName($to));
			$db->execute();
		};
		$rename($table, $table.'_off');
		try
		{
			return $test();
		}
		finally
		{
			$rename($table.'_off', $table);
		}
	}

	public function testLoginAttemptIsRefusedIfTheBlockListCantBeRead()
	{
		// "can't tell" must not pass for "not blocked" where it matters: a
		// login attempt is refused (503, so not for good); browsing goes on
		$this->configure();
		list($login, $page) = $this->withoutBlockTable(function ()
		{
			return array($this->request('option=com_users&task=user.login'), $this->request('option=com_content'));
		});
		$this->assertStringNotContainsString('NOT BLOCKED', $login);
		$this->assertStringContainsString('STATUS: 503', $login);
		$this->assertStringContainsString('NOT BLOCKED', $page);
	}
}
