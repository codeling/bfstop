<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Joomla\CMS\Event\User\LoginEvent;
use Joomla\CMS\Event\User\LoginFailureEvent;
use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
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
		'delayDuration' => 0,
		'riskDelaySecondsPerPoint' => 0,
		'riskBlockNumberReductionPerPoint' => 0,
		'accountThrottleEnabled' => 0,
		'notifyBlockedNumber' => 0,
		'logLevel' => 8, // errors only
	);

	private static $originalParams;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
		$db->setQuery("SELECT params FROM #__extensions WHERE type='plugin' AND element='bfstop'");
		self::$originalParams = $db->loadResult();
		$db->setQuery('UPDATE #__extensions SET params='.$db->quote(json_encode(self::Params)).
			", enabled=1 WHERE type='plugin' AND element='bfstop'");
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
			$db->setQuery('UPDATE #__extensions SET params='.$db->quote(self::$originalParams).
				" WHERE type='plugin' AND element='bfstop'");
			$db->execute();
		}
	}

	private function dispatch($eventName, array $arguments)
	{
		// the login events as Joomla's CMSApplication::login() dispatches them
		$classes = array('onUserLogin' => LoginEvent::class, 'onUserLoginFailure' => LoginFailureEvent::class);
		$event = isset($classes[$eventName])
			? new $classes[$eventName]($eventName, array('subject' => $arguments[0], 'options' => $arguments[1]))
			: new Event($eventName, $arguments);
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
