<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Joomla\CMS\Factory;

/**
 * Logins with a wrong password sent all at once, as real HTTP requests to
 * PHP's built-in web server running the Joomla site with several workers:
 * no more of them may get their password checked than attempts are allowed
 * (see Bfstop::awaitLoginTurn()). Like UnblockPageHttpTest, this runs the
 * plugin as installed in the Joomla site, not the source checkout.
 */
class ParallelLoginHttpTest extends IntegrationTestCase
{
	private const Logins = 12;
	private const Allowed = 3;

	private static $originalParams;
	private $server;
	private $port;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		if (!function_exists('curl_multi_init'))
		{
			self::markTestSkipped('needs the curl extension');
		}
		if (DIRECTORY_SEPARATOR === '\\')
		{
			self::markTestSkipped('the built-in web server has no workers on Windows');
		}
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
		$this->setPluginParams(json_encode(array(
			'blockMode' => 'full',
			'blockNumber' => self::Allowed,
			'checkInterval' => 60,
			'blockDuration' => 60,
			'delayDuration' => 0,
			'accountThrottleEnabled' => 0,
			'riskBlockNumberReductionPerPoint' => 0,
			'riskDelaySecondsPerPoint' => 0,
			'notifyBlockedNumber' => 0,
			'logLevel' => 8, // errors only
		)));
		$listener = stream_socket_server('tcp://127.0.0.1:0');
		$this->port = (int) substr(strrchr(stream_socket_get_name($listener, false), ':'), 1);
		fclose($listener);
		// a worker for every login: they are all being handled at the same time
		$this->server = proc_open('exec '.escapeshellarg(PHP_BINARY).' -S 127.0.0.1:'.$this->port.' -t '.
			escapeshellarg(getenv('JOOMLA_ROOT')), array(0 => array('file', '/dev/null', 'r'),
			1 => array('file', '/dev/null', 'w'), 2 => array('file', '/dev/null', 'w')), $pipes, null,
			array('PHP_CLI_SERVER_WORKERS' => self::Logins) + getenv());
		for ($i = 0; $i < 50; ++$i)
		{
			if (($socket = @fsockopen('127.0.0.1', $this->port)) !== false)
			{
				fclose($socket);
				return;
			}
			usleep(100000);
		}
		$this->markTestSkipped('could not start the PHP web server');
	}

	protected function tearDown(): void
	{
		if ($this->server)
		{
			proc_terminate($this->server);
			proc_close($this->server);
		}
	}

	private function url($query)
	{
		return 'http://127.0.0.1:'.$this->port.'/index.php?'.$query;
	}

	/**
	 * A visitor who opened the login form: the session cookie and the name
	 * of the form's token.
	 */
	private function visitor()
	{
		$curl = curl_init($this->url('option=com_users&view=login'));
		// Joomla may redirect to the form's search-engine-friendly address;
		// '' keeps the cookies in memory
		curl_setopt_array($curl, array(CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true,
			CURLOPT_COOKIEFILE => '', CURLOPT_USERAGENT => 'Mozilla/5.0'));
		$response = (string) curl_exec($curl);
		$this->assertSame(200, curl_getinfo($curl, CURLINFO_HTTP_CODE), 'the login form');
		$cookies = array();
		foreach (curl_getinfo($curl, CURLINFO_COOKIELIST) as $line)
		{
			// Netscape format: ..., name, value
			$fields = explode("\t", $line);
			$cookies[] = $fields[5].'='.$fields[6];
		}
		$this->assertNotEmpty($cookies, 'session cookie');
		$this->assertSame(1, preg_match('/name="([a-f0-9]{32})" value="1"/', $response, $token), 'form token');
		return array(implode('; ', $cookies), $token[1]);
	}

	public function testNoMoreLoginsAreCheckedAtOnceThanAttemptsAreAllowed()
	{
		$multi = curl_multi_init();
		$logins = array();
		for ($i = 0; $i < self::Logins; ++$i)
		{
			list($cookie, $token) = $this->visitor();
			$curl = curl_init($this->url('option=com_users&task=user.login'));
			curl_setopt_array($curl, array(CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIE => $cookie,
				CURLOPT_USERAGENT => 'Mozilla/5.0', CURLOPT_POST => true,
				CURLOPT_POSTFIELDS => http_build_query(array('username' => 'Admin', 'password' => 'wrong'.$i, $token => 1))));
			curl_multi_add_handle($multi, $curl);
			$logins[] = $curl;
		}
		do
		{
			curl_multi_exec($multi, $running);
			curl_multi_select($multi, 0.1);
		}
		while ($running > 0);
		$statuses = array();
		foreach ($logins as $curl)
		{
			$status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
			$statuses[$status] = ($statuses[$status] ?? 0) + 1;
		}
		ksort($statuses);

		$this->assertSame(self::Allowed, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'),
			'every failed login recorded is a password which was checked');
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'));
		// back to the login form for those which were checked, the block page
		// for the others
		$this->assertSame(array(303 => self::Allowed, 403 => self::Logins - self::Allowed), $statuses);
	}
}
