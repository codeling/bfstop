<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Extension\Bfstop;
use Codeling\Plugin\System\Bfstop\Helper\LockHelper;
use Joomla\CMS\Factory;

/**
 * Logins from one address are handled one after the other (see
 * Bfstop::awaitLoginTurn()): a failed login is only counted after its
 * password was checked, so logins sent at the same time would otherwise all
 * be checked, however few attempts are allowed. The test stands in for the
 * login before the one it sends - it holds the lock of the address - and
 * each request runs in a process of its own (see fixtures/request.php).
 * ParallelLoginHttpTest does the same with real logins.
 */
class LoginTurnTest extends IntegrationTestCase
{
	private const BlockedMessage = 'BFSTOP TEST: blocked';
	private const Ip = '203.0.113.61';
	private const Login = 'option=com_users&task=user.login';

	private static $originalParams;
	private $turn = null;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
		$db->setQuery("SELECT params FROM #__extensions WHERE type='plugin' AND element='bfstop'");
		self::$originalParams = $db->loadResult();
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

	protected function setUp(): void
	{
		parent::setUp();
		$this->configure();
	}

	protected function tearDown(): void
	{
		LockHelper::release($this->turn);
	}

	private function configure(array $params = array())
	{
		$this->setPluginParams(json_encode($params + array(
			'blockMode' => 'full',
			'blockNumber' => 3,
			'blockedMessage' => self::BlockedMessage,
			'delayDuration' => 0,
			'accountThrottleEnabled' => 0,
			'riskBlockNumberReductionPerPoint' => 0,
			'notifyBlockedNumber' => 0,
			'logLevel' => 8, // errors only
		)));
	}

	/** as the login of the address which is being handled right now */
	private function holdTurn($ip = self::Ip)
	{
		$this->turn = LockHelper::acquire(Bfstop::loginTurnFile($ip), 0);
		$this->assertIsResource($this->turn);
	}

	private function endTurn()
	{
		LockHelper::release($this->turn);
		$this->turn = null;
	}

	/** @return array the process and the pipe of its output */
	private function start($query, array $options = array())
	{
		$command = array_merge(array(PHP_BINARY, __DIR__.'/fixtures/request.php', self::Ip, $query), $options);
		$process = proc_open($command, array(1 => array('pipe', 'w'), 2 => array('redirect', 1)), $pipes);
		$this->assertIsResource($process);
		return array($process, $pipes[1]);
	}

	private function finish(array $started)
	{
		$output = stream_get_contents($started[1]);
		fclose($started[1]);
		proc_close($started[0]);
		return $output;
	}

	/** @return array the output and how long the request took, in seconds */
	private function request($query, array $options = array())
	{
		$start = microtime(true);
		$output = $this->finish($this->start($query, $options));
		return array($output, microtime(true) - $start);
	}

	private function assertWaits(array $started)
	{
		// long enough for the request to get as far as it gets
		usleep(1500000);
		$this->assertTrue(proc_get_status($started[0])['running'], 'the request waits for the login before it');
	}

	private function assertDoesNotWait($query, array $options = array(), $message = '')
	{
		list($output, $seconds) = $this->request($query, $options);
		$this->assertStringContainsString('NOT BLOCKED', $output, $message);
		$this->assertLessThan(Bfstop::LoginTurnWaitSeconds - 1, $seconds, $message);
	}

	public function testLoginSeesTheBlockOfTheLoginBeforeIt()
	{
		$this->holdTurn();
		$login = $this->start(self::Login);
		$this->assertWaits($login);
		// the login before it failed, which was one too many
		$this->insert('#__bfstop_bannedip', array('ipaddress' => self::Ip,
			'crdate' => self::minutesAgo(0), 'duration' => 60));
		$this->endTurn();
		$output = $this->finish($login);
		$this->assertStringContainsString(self::BlockedMessage, $output);
		$this->assertStringContainsString('STATUS: 403', $output);
	}

	public function testLoginIsHandledOnceTheOneBeforeItIsDone()
	{
		$this->holdTurn();
		$login = $this->start(self::Login);
		$this->assertWaits($login);
		$this->endTurn();
		$this->assertStringContainsString('NOT BLOCKED', $this->finish($login));
	}

	public function testBackendAndApiPasswordLoginsWaitToo()
	{
		$this->holdTurn();
		$backend = $this->start('task=login', array('--admin'));
		$api = $this->start('', array('--api', '--server=PHP_AUTH_USER=Admin', '--server=PHP_AUTH_PW=x'));
		$this->assertWaits($backend);
		$this->assertTrue(proc_get_status($api[0])['running']);
		$this->endTurn();
		$this->assertStringContainsString('NOT BLOCKED', $this->finish($backend));
		$this->assertStringContainsString('NOT BLOCKED', $this->finish($api));
	}

	public function testOnlyPasswordLoginsWait()
	{
		$this->holdTurn();
		$this->assertDoesNotWait('option=com_users&view=login', array(), 'showing the login form');
		$this->assertDoesNotWait('option=com_content&view=featured', array(), 'any other page');
		$this->assertDoesNotWait('', array('--api'), 'API request without credentials');
		$this->assertDoesNotWait('', array('--api', '--server=HTTP_AUTHORIZATION=Bearer c2hhMjU2OjQyOmFiYw=='),
			'API request with a token');
	}

	public function testLoginsOfOtherAddressesDoNotWait()
	{
		// unless they share the lock file, which 1 in Bfstop::LoginTurnSlots
		// does - which ones depends on the site's secret, a new one on every
		// test site: so the other address is one with a lock file of its own
		$file = Bfstop::loginTurnFile(self::Ip);
		$other = null;
		for ($i = 1; $i < 256 && $other === null; ++$i)
		{
			if (Bfstop::loginTurnFile('198.51.100.'.$i) !== $file)
			{
				$other = '198.51.100.'.$i;
			}
		}
		$this->assertNotNull($other, 'an address with another lock file');
		$this->holdTurn($other);
		$this->assertDoesNotWait(self::Login);
	}

	public function testNoWaitingIfNothingIsBlocked()
	{
		$this->configure(array('blockMode' => 'off'));
		$this->holdTurn();
		$this->assertDoesNotWait(self::Login);
	}

	public function testAllowedAddressesDoNotWait()
	{
		$this->insert('#__bfstop_allowlist', array('ipaddress' => self::Ip, 'notes' => ''));
		$this->holdTurn();
		$this->assertDoesNotWait(self::Login);
	}

	public function testLoginIsHandledAnywayWhenTheWaitIsOver()
	{
		// e.g. the login before it hangs in a slow authentication plugin
		$this->holdTurn();
		list($output, $seconds) = $this->request(self::Login);
		$this->assertStringContainsString('NOT BLOCKED', $output);
		$this->assertGreaterThanOrEqual(Bfstop::LoginTurnWaitSeconds, $seconds);
	}

	public function testTurnEndsWhenTheFailedLoginIsCounted()
	{
		list($output) = $this->request(self::Login, array('--then=failure:Admin'));
		$this->assertStringContainsString("NOT BLOCKED\nLOGIN TURN HELD\nLOGIN TURN FREE", $output);
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'));
	}

	public function testTurnEndsWhenTheLoginSucceeds()
	{
		list($output) = $this->request(self::Login, array('--then=login:Admin'));
		$this->assertStringContainsString("NOT BLOCKED\nLOGIN TURN HELD\nLOGIN TURN FREE", $output);
	}

	public function testOtherRequestsTakeNoTurn()
	{
		list($output) = $this->request('option=com_users&view=login', array('--then=failure:Admin'));
		$this->assertStringContainsString("NOT BLOCKED\nLOGIN TURN FREE\nLOGIN TURN FREE", $output);
	}

	public function testEveryAddressHasOneOfAFixedNumberOfLockFiles()
	{
		$files = array();
		for ($i = 0; $i < 2000; ++$i)
		{
			$files[Bfstop::loginTurnFile('198.51.'.($i >> 8).'.'.($i & 255))] = true;
		}
		$this->assertLessThanOrEqual(Bfstop::LoginTurnSlots, count($files));
		$this->assertGreaterThan(Bfstop::LoginTurnSlots / 2, count($files), 'spread over the files');
		$this->assertSame(Bfstop::loginTurnFile('2001:db8:1:200::/56'), Bfstop::loginTurnFile('2001:db8:1:200::/56'));
		$this->assertStringStartsWith(Factory::getApplication()->get('tmp_path'), Bfstop::loginTurnFile(self::Ip));
	}
}
