<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Service\MfaGate;
use Joomla\CMS\Event\MultiFactor\NotifyActionLog;
use Joomla\CMS\Event\User\LoginEvent;
use Joomla\CMS\Event\User\LoginFailureEvent;
use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\User\User;
use Joomla\DI\Container;
use Joomla\Event\Dispatcher;
use Joomla\Event\Event;

/**
 * The plugin as Joomla runs it: loaded through its service provider, with
 * its settings read from the database, reacting to dispatched events.
 */
class PluginEventsTest extends IntegrationTestCase
{
	private const Params = array(
		'blockMode' => 'full',
		'blockNumber' => 3,
		'checkInterval' => 60,
		'blockDuration' => 60,
		'riskBlockNumberReductionPerPoint' => 0,
		'accountAttackEnabled' => 0,
		'notifyBlockedNumber' => 0,
		'logLevel' => 8, // errors only
	);

	private static $originalParams;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
		$db->setQuery("SELECT params FROM #__extensions WHERE type='component' AND element='com_bfstop'");
		self::$originalParams = $db->loadResult();
		self::storeSettings($db, json_encode(self::Params));
		$db->setQuery("UPDATE #__extensions SET enabled=1 WHERE type='plugin' AND element='bfstop'");
		$db->execute();
		// forget the plugin list possibly already loaded with the old params
		(new \ReflectionProperty(PluginHelper::class, 'plugins'))->setValue(null, null);
		$app = Factory::getApplication();
		PluginHelper::importPlugin('system', 'bfstop', true, $app->getDispatcher());
	}

	public static function tearDownAfterClass(): void
	{
		if (self::$originalParams !== null)
		{
			$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
			self::storeSettings($db, self::$originalParams);
		}
	}

	private function dispatch($eventName, array $arguments)
	{
		// the login events as Joomla's CMSApplication::login() dispatches them
		$classes = array('onUserLogin' => LoginEvent::class, 'onUserLoginFailure' => LoginFailureEvent::class);
		if (str_starts_with($eventName, 'onComUsersCaptive'))
		{
			// as the captive controller dispatches them
			$event = new NotifyActionLog($eventName, $arguments);
		}
		else
		{
			$event = isset($classes[$eventName])
				? new $classes[$eventName]($eventName, array('subject' => $arguments[0], 'options' => $arguments[1]))
				: new Event($eventName, $arguments);
		}
		Factory::getApplication()->getDispatcher()->dispatch($eventName, $event);
	}

	private function failedLogin($ip, $username)
	{
		$_SERVER['REMOTE_ADDR'] = $ip;
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
		$this->dispatch('onUserLoginFailure', array(array('username' => $username, 'status' => 4), array()));
	}

	/**
	 * Runs a request from the given IP address in a separate process, since
	 * the plugin ends a blocked request with exit(); returns its output.
	 */
	private function requestFrom($ip)
	{
		$command = escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/fixtures/request.php').' '.escapeshellarg($ip).' 2>&1';
		exec($command, $output, $exitCode);
		$output = implode("\n", $output);
		$this->assertSame(0, $exitCode, $output);
		return $output;
	}

	private function pluginLogErrors()
	{
		$file = Factory::getApplication()->get('log_path').'/plg_system_bfstop.log.php';
		return is_file($file) ? substr_count(file_get_contents($file), ' ERROR ') : 0;
	}

	public function testBlocksAfterTooManyFailedLogins()
	{
		$logErrorsBefore = $this->pluginLogErrors();
		$ip = '203.0.113.21';
		$this->failedLogin($ip, 'Admin');
		$this->failedLogin($ip, 'Admin');
		$this->assertSame(2, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'));
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
		$this->failedLogin($ip, 'Admin');
		$this->assertSame($ip, $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));

		$this->assertStringContainsString('has been blocked', $this->requestFrom($ip));
		$this->assertSame(1, (int) $this->queryValue('SELECT attempts FROM #__bfstop_bannedip'));
		$this->assertStringContainsString('NOT BLOCKED', $this->requestFrom('203.0.113.22'));

		$this->assertSame($logErrorsBefore, $this->pluginLogErrors(), 'plugin logged errors');
	}

	public function testFailedLoginWithoutUsernameIsRecorded()
	{
		// some authentication flows hand over credentials without a username
		$_SERVER['REMOTE_ADDR'] = '203.0.113.23';
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
		$this->dispatch('onUserLoginFailure', array(array('status' => 4), array()));
		$this->assertSame(1, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE ipaddress='203.0.113.23'"));
	}

	public function testSubnetBlockAndAllowList()
	{
		$this->insert('#__bfstop_bannedip', array('ipaddress' => '198.51.100.0/24', 'crdate' => self::minutesAgo(0), 'duration' => 0));
		$this->insert('#__bfstop_allowlist', array('ipaddress' => '198.51.100.128/25', 'notes' => ''));
		$this->assertStringContainsString('has been blocked', $this->requestFrom('198.51.100.1'));
		$this->assertStringContainsString('NOT BLOCKED', $this->requestFrom('198.51.100.200'), 'allow list wins');
	}

	public function testSuccessfulLoginRecordsKnownIp()
	{
		$_SERVER['REMOTE_ADDR'] = '203.0.113.30';
		$this->dispatch('onUserLogin', array(array('username' => 'Admin'), array()));
		$this->assertSame('Admin', $this->queryValue("SELECT username FROM #__bfstop_knownip WHERE ipaddress='203.0.113.30'"));
	}

	public function testSuccessfulLoginOfAnIpv6ClientIsRememberedByNetwork()
	{
		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::77';
		$this->dispatch('onUserLogin', array(array('username' => 'Admin'), array()));
		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2:abcd::1'; // the next day's privacy address
		$this->dispatch('onUserLogin', array(array('username' => 'Admin'), array()));
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip'));
		// a /64, not the /56 failed logins are counted by: others may share the /56
		$this->assertSame('2001:db8:1:2::/64', $this->queryValue('SELECT ipaddress FROM #__bfstop_knownip'));
	}

	public function testSuccessfulLoginHandlesTheFailedLoginsOfItsNetwork()
	{
		$this->failedLogin('2001:db8:1:2::1', 'Admin');
		$this->failedLogin('2001:db8:1:2::2', 'Admin');
		$this->assertSame(2, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE handled=0'));
		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::3';
		$this->dispatch('onUserLogin', array(array('username' => 'Admin'), array()));
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE handled=0'));
	}

	/**
	 * Gives the account a multi-factor authentication method, as Joomla
	 * stores it. The options matter: Joomla ignores a record without any (it
	 * can't be used), so that the user would have no MFA at all.
	 */
	private function addMfaRecord($userId)
	{
		$this->insert('#__user_mfa', array('user_id' => $userId, 'title' => 'Test', 'method' => 'totp',
			'default' => 1, 'options' => '{"key":"JBSWY3DPEHPK3PXP"}', 'created_on' => self::minutesAgo(0)));
	}

	/** what is left in the session and the identity by a test of the MFA gate */
	private function cleanUpMfaTest($userId)
	{
		$app = Factory::getApplication();
		$session = $app->getSession();
		$session->clear(MfaGate::CheckedKey);
		$session->clear(MfaGate::HeldKey);
		$app->loadIdentity(new User());
		$this->db->setQuery('DELETE FROM #__user_mfa WHERE user_id='.$userId);
		$this->db->execute();
	}

	/**
	 * Joomla dispatches onUserLogin when the password is right; the second
	 * factor comes with later requests (issue #342, finding 4). Until Joomla
	 * says that it is done (its session flag), the login is no success:
	 * the address isn't remembered and its failed logins keep counting.
	 */
	public function testLoginOfAUserWithMfaCountsOnceTheMfaIsDone()
	{
		$userId = (int) $this->queryValue("SELECT id FROM #__users WHERE username='Admin'");
		$this->assertGreaterThan(0, $userId);
		$this->addMfaRecord($userId);
		$ip = '203.0.113.50';
		$app = Factory::getApplication();
		try
		{
			$this->failedLogin($ip, 'Admin');
			$this->failedLogin($ip, 'Admin');
			$this->dispatch('onUserLogin', array(array('username' => 'Admin', 'email' => 'admin@example.org'), array()));
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip'),
				'a correct password alone makes the address a known one');
			$this->assertSame(2, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE handled=0'),
				'a correct password alone forgets the failed logins');

			// the requests after it, while Joomla asks for the second factor
			$app->loadIdentity(User::getInstance($userId));
			$this->dispatch('onAfterDispatch', array());
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip'));
			$this->assertSame(2, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE handled=0'));

			// the second factor is validated: Joomla sets its flag
			$app->getSession()->set(MfaGate::CheckedKey, 1);
			$this->dispatch('onAfterDispatch', array());
			$this->assertSame('Admin', $this->queryValue("SELECT username FROM #__bfstop_knownip WHERE ipaddress='$ip'"));
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE handled=0'));
		}
		finally
		{
			$this->cleanUpMfaTest($userId);
		}
	}

	/** the login held back is completed once, not by every request after it */
	public function testLoginHeldBackForMfaIsCompletedOnce()
	{
		$userId = (int) $this->queryValue("SELECT id FROM #__users WHERE username='Admin'");
		$this->addMfaRecord($userId);
		$app = Factory::getApplication();
		try
		{
			$_SERVER['REMOTE_ADDR'] = '203.0.113.52';
			$this->dispatch('onUserLogin', array(array('username' => 'Admin'), array()));
			$app->loadIdentity(User::getInstance($userId));
			$app->getSession()->set(MfaGate::CheckedKey, 1);
			$this->dispatch('onAfterDispatch', array());
			$this->assertSame(1, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_knownip WHERE ipaddress='203.0.113.52'"));
			// another address, with nothing held back any more
			$_SERVER['REMOTE_ADDR'] = '203.0.113.53';
			$this->dispatch('onAfterDispatch', array());
			$this->assertSame(0, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_knownip WHERE ipaddress='203.0.113.53'"));
		}
		finally
		{
			$this->cleanUpMfaTest($userId);
		}
	}

	/**
	 * The login held back is completed for the user it was for, and only for
	 * one who is still logged in with the flag set.
	 */
	public function testLoginHeldBackForMfaIsNotCompletedForAnotherUser()
	{
		$userId = (int) $this->queryValue("SELECT id FROM #__users WHERE username='Admin'");
		$this->addMfaRecord($userId);
		$app = Factory::getApplication();
		try
		{
			$_SERVER['REMOTE_ADDR'] = '203.0.113.51';
			$this->dispatch('onUserLogin', array(array('username' => 'Admin'), array()));
			$app->getSession()->set(MfaGate::CheckedKey, 1);
			// nobody logged in: a guest's request completes nothing
			$this->dispatch('onAfterDispatch', array());
			$other = new User();
			$other->id = $userId + 1000;
			$other->guest = 0;
			$other->username = 'somebody-else';
			$app->loadIdentity($other);
			$this->dispatch('onAfterDispatch', array());
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip'));
		}
		finally
		{
			$this->cleanUpMfaTest($userId);
		}
	}

	/** a login held back for a day or more is not completed any more */
	public function testLoginHeldBackForMfaExpires()
	{
		$userId = (int) $this->queryValue("SELECT id FROM #__users WHERE username='Admin'");
		$this->addMfaRecord($userId);
		$app = Factory::getApplication();
		try
		{
			$_SERVER['REMOTE_ADDR'] = '203.0.113.54';
			$app->getSession()->set(MfaGate::HeldKey, json_encode(array('username' => 'Admin', 'email' => '',
				'time' => time() - MfaGate::MaxAgeSeconds - 60)));
			$app->loadIdentity(User::getInstance($userId));
			$app->getSession()->set(MfaGate::CheckedKey, 1);
			$this->dispatch('onAfterDispatch', array());
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip'));
		}
		finally
		{
			$this->cleanUpMfaTest($userId);
		}
	}

	/**
	 * A user who logs in again (or whose account has no MFA) supersedes the
	 * login held back: it is not completed later.
	 */
	public function testLoginWithoutMfaSupersedesTheOneHeldBack()
	{
		$userId = (int) $this->queryValue("SELECT id FROM #__users WHERE username='Admin'");
		$this->addMfaRecord($userId);
		$app = Factory::getApplication();
		try
		{
			$_SERVER['REMOTE_ADDR'] = '203.0.113.55';
			$this->dispatch('onUserLogin', array(array('username' => 'Admin'), array()));
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip'));
			// the account of the next login has no MFA: counted at once
			$this->dispatch('onUserLogin', array(array('username' => 'nobody-with-mfa'), array()));
			$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip'));
			$this->assertFalse($app->getSession()->has(MfaGate::HeldKey));
		}
		finally
		{
			$this->cleanUpMfaTest($userId);
		}
	}

	/** logs the user in, as far as Joomla's identity goes: what a request after the password has */
	private function loginIdentity($username)
	{
		$user = User::getInstance((int) $this->queryValue("SELECT id FROM #__users WHERE username='".$username."'"));
		Factory::getApplication()->loadIdentity($user);
	}

	/**
	 * A wrong second factor is a failed login of the user logged in with the
	 * password (issue #342, finding 4): counted towards the block of the
	 * address like a wrong password, whether the code was wrong or the limit
	 * of tries of the method was reached.
	 */
	public function testWrongSecondFactorCountsLikeAFailedPassword()
	{
		$ip = '203.0.113.60';
		$_SERVER['REMOTE_ADDR'] = $ip;
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
		try
		{
			$this->loginIdentity('Admin');
			$this->dispatch('onComUsersCaptiveValidateFailed', array('Test'));
			$this->dispatch('onComUsersCaptiveValidateFailed', array('Test'));
			$this->assertSame(2, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE ipaddress='$ip' AND username='Admin'"));
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
			$this->dispatch('onComUsersCaptiveValidateTryLimitReached', array());
			$this->assertSame($ip, $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));
		}
		finally
		{
			Factory::getApplication()->loadIdentity(new User());
		}
	}

	/**
	 * The strongest signal: failed passwords of an address, then the
	 * password right and the second factor wrong. The login of a user with
	 * multi-factor authentication doesn't make those forgotten before the
	 * second factor is done, so they add to the wrong code.
	 */
	public function testWrongSecondFactorAddsToTheFailedPasswordsOfTheAddress()
	{
		$userId = (int) $this->queryValue("SELECT id FROM #__users WHERE username='Admin'");
		$this->addMfaRecord($userId);
		$ip = '203.0.113.61';
		try
		{
			$this->failedLogin($ip, 'Admin');
			$this->failedLogin($ip, 'Admin');
			$this->dispatch('onUserLogin', array(array('username' => 'Admin'), array()));
			Factory::getApplication()->loadIdentity(User::getInstance($userId));
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
			$this->dispatch('onComUsersCaptiveValidateFailed', array('Test'));
			$this->assertSame($ip, $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));
		}
		finally
		{
			$this->cleanUpMfaTest($userId);
		}
	}

	/** the second factor of a login done after wrong ones makes them forgotten, as it does the passwords */
	public function testSecondFactorDoneMakesTheWrongCodesForgotten()
	{
		$userId = (int) $this->queryValue("SELECT id FROM #__users WHERE username='Admin'");
		$this->addMfaRecord($userId);
		$ip = '203.0.113.62';
		try
		{
			$_SERVER['REMOTE_ADDR'] = $ip;
			$this->dispatch('onUserLogin', array(array('username' => 'Admin'), array()));
			Factory::getApplication()->loadIdentity(User::getInstance($userId));
			$this->dispatch('onComUsersCaptiveValidateFailed', array('Test'));
			$this->dispatch('onComUsersCaptiveValidateFailed', array('Test'));
			$this->assertSame(2, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE handled=0'));
			Factory::getApplication()->getSession()->set(MfaGate::CheckedKey, 1);
			$this->dispatch('onAfterDispatch', array());
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE handled=0'));
		}
		finally
		{
			$this->cleanUpMfaTest($userId);
		}
	}

	/** nobody logged in, or the address allowed: nothing to count */
	public function testWrongSecondFactorOfNobodyOrAnAllowedAddressIsNotCounted()
	{
		$_SERVER['REMOTE_ADDR'] = '203.0.113.63';
		$this->dispatch('onComUsersCaptiveValidateFailed', array('Test'));
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'), 'a guest');
		$this->insert('#__bfstop_allowlist', array('ipaddress' => '203.0.113.63', 'notes' => ''));
		try
		{
			$this->loginIdentity('Admin');
			$this->dispatch('onComUsersCaptiveValidateFailed', array('Test'));
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'), 'an allowed address');
		}
		finally
		{
			Factory::getApplication()->loadIdentity(new User());
		}
	}

	/**
	 * The plugin built the way Joomla builds it (services/provider.php) and
	 * the login events as Joomla dispatches them, without a deprecation
	 * notice. Joomla raises most of them silenced (@trigger_error), which
	 * phpunit doesn't report, so they are collected here - those of what
	 * BFStop calls: Joomla 5.4 also uses deprecated APIs itself (e.g.
	 * DatabaseDriver::setQuery() calls getQuery(true)).
	 */
	public function testIsBuiltAndHandlesLoginsWithoutDeprecations()
	{
		$deprecations = array();
		$libraries = realpath(JPATH_LIBRARIES).'/';
		set_error_handler(function ($errno, $message) use (&$deprecations, $libraries)
		{
			$trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
			foreach ($trace as $i => $frame)
			{
				if (in_array($frame['function'], array('trigger_error', 'trigger_deprecation'), true))
				{
					// where the deprecated function was called from
					$caller = (string) ($trace[$i + 1]['file'] ?? '');
					if (!str_starts_with((string) realpath($caller), $libraries))
					{
						$deprecations[] = $message.' ('.$caller.':'.($trace[$i + 1]['line'] ?? '?').')';
					}
					break;
				}
			}
			return true;
		}, E_DEPRECATED | E_USER_DEPRECATED);
		try
		{
			$container = new Container();
			(require BFSTOP_PLUGIN_ROOT.'/services/provider.php')->register($container);
			$plugin = $container->get(PluginInterface::class);
			// as PluginHelper::import() does it from Joomla 6.0 on
			$dispatcher = new Dispatcher();
			$dispatcher->addSubscriber($plugin);
			$_SERVER['REMOTE_ADDR'] = '203.0.113.40';
			$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
			$dispatcher->dispatch('onUserLoginFailure', new LoginFailureEvent('onUserLoginFailure',
				array('subject' => array('username' => 'Admin', 'status' => 4), 'options' => array())));
			$dispatcher->dispatch('onUserLogin', new LoginEvent('onUserLogin',
				array('subject' => array('username' => 'Admin', 'status' => 1), 'options' => array())));
		}
		finally
		{
			restore_error_handler();
		}
		$this->assertSame(array(), $deprecations, implode("\n", $deprecations));
		$this->assertSame(1, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE ipaddress='203.0.113.40' AND handled=1"));
		$this->assertSame('Admin', $this->queryValue("SELECT username FROM #__bfstop_knownip WHERE ipaddress='203.0.113.40'"));
	}
}
