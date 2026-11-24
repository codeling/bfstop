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
 * The login of a user with multi-factor authentication, as real HTTP
 * requests to PHP's built-in web server running the Joomla site (issue #342,
 * finding 4): the address only becomes a known one, and its failed logins
 * are only forgotten, once Joomla has the second factor. PluginEventsTest
 * checks the plugin's side with the session flag set by hand; this is what
 * shows that Joomla - on every version of the matrix - sets it the way
 * MfaGate expects: reset at the login, set by the captive page. Like
 * UnblockPageHttpTest, this runs the plugin as installed in the Joomla site,
 * not the source checkout.
 */
class MfaLoginHttpTest extends IntegrationTestCase
{
	// base32 of a secret key, as the TOTP method of Joomla stores it
	private const TotpKey = 'JBSWY3DPEHPK3PXP';
	private const Password = 'bfstop-test-password';

	private static $originalParams;
	private $server;
	private $port;
	private $curl;
	private $userId;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		if (DIRECTORY_SEPARATOR === '\\')
		{
			self::markTestSkipped('the test starts the built-in web server like the other HTTP tests');
		}
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

	protected function setUp(): void
	{
		parent::setUp();
		$this->setSettings(json_encode(array(
			'blockMode' => 'full',
			'blockNumber' => 5,
			'checkInterval' => 60,
			'blockDuration' => 60,
			'accountAttackEnabled' => 0,
			'riskBlockNumberReductionPerPoint' => 0,
			'notifyBlockedNumber' => 0,
			'logLevel' => 8, // errors only
		)));
		$this->userId = (int) $this->queryValue("SELECT id FROM #__users WHERE username='Admin'");
		$this->db->setQuery('DELETE FROM #__user_mfa WHERE user_id='.$this->userId);
		$this->db->execute();
		$this->insert('#__user_mfa', array('user_id' => $this->userId, 'title' => 'Test', 'method' => 'totp',
			'default' => 1, 'options' => json_encode(array('key' => self::TotpKey)), 'created_on' => self::minutesAgo(0)));
		// the failed logins of the address the requests come from
		for ($i = 0; $i < 2; ++$i)
		{
			$this->insert('#__bfstop_failedlogin', array('username' => 'Admin', 'ipaddress' => '127.0.0.1',
				'logtime' => self::minutesAgo(1), 'origin' => 1, 'handled' => 0));
		}

		$listener = stream_socket_server('tcp://127.0.0.1:0');
		$this->port = (int) substr(strrchr(stream_socket_get_name($listener, false), ':'), 1);
		fclose($listener);
		$this->server = proc_open('exec '.escapeshellarg(PHP_BINARY).' -S 127.0.0.1:'.$this->port.' -t '.
			escapeshellarg(getenv('JOOMLA_ROOT')), array(0 => array('file', '/dev/null', 'r'),
			1 => array('file', '/dev/null', 'w'), 2 => array('file', '/dev/null', 'w')), $pipes);
		for ($i = 0; $i < 50; ++$i)
		{
			if (($socket = @fsockopen('127.0.0.1', $this->port)) !== false)
			{
				fclose($socket);
				// one client: its cookies (the session) are kept in memory, redirects are not followed
				$this->curl = curl_init();
				curl_setopt_array($this->curl, array(CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEFILE => '',
					CURLOPT_USERAGENT => 'Mozilla/5.0'));
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
		// what the other tests, which log in as Admin, must not find
		$this->db->setQuery('DELETE FROM #__user_mfa WHERE user_id='.$this->userId);
		$this->db->execute();
	}

	/** @return array{0: int, 1: string} the status and the body */
	private function request($query, array $post = null)
	{
		curl_setopt($this->curl, CURLOPT_URL, 'http://127.0.0.1:'.$this->port.'/index.php?'.$query);
		curl_setopt($this->curl, CURLOPT_POST, $post !== null);
		curl_setopt($this->curl, CURLOPT_POSTFIELDS, $post !== null ? http_build_query($post) : null);
		$body = (string) curl_exec($this->curl);
		return array(curl_getinfo($this->curl, CURLINFO_HTTP_CODE), $body);
	}

	private function formToken($body)
	{
		$this->assertSame(1, preg_match('/name="([a-f0-9]{32})" value="1"/', $body, $token), 'form token');
		return $token[1];
	}

	/** the code of the TOTP method (RFC 6238: SHA-1, 6 digits, 30 seconds) for now */
	private static function totpCode()
	{
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$bits = '';
		foreach (str_split(self::TotpKey) as $c)
		{
			$bits .= str_pad(decbin(strpos($alphabet, $c)), 5, '0', STR_PAD_LEFT);
		}
		$key = '';
		foreach (str_split($bits, 8) as $byte)
		{
			if (strlen($byte) === 8)
			{
				$key .= chr(bindec($byte));
			}
		}
		$hash = hash_hmac('sha1', pack('J', intdiv(time(), 30)), $key, true);
		$offset = ord($hash[19]) & 15;
		$value = ((ord($hash[$offset]) & 0x7f) << 24) | (ord($hash[$offset + 1]) << 16) |
			(ord($hash[$offset + 2]) << 8) | ord($hash[$offset + 3]);
		return sprintf('%06d', $value % 1000000);
	}

	private function knownAddresses()
	{
		return (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip');
	}

	private function unhandledFailedLogins()
	{
		return (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin WHERE handled=0');
	}

	/**
	 * Logs in with the password and opens the captive page which asks for the
	 * second factor.
	 *
	 * @return array the parameters of the request which validates a code
	 */
	private function loginWithPassword()
	{
		list($status, $body) = $this->request('option=com_users&view=login');
		$this->assertSame(200, $status, 'the login form');
		list($status) = $this->request('option=com_users&task=user.login', array('username' => 'Admin',
			'password' => self::Password, $this->formToken($body) => 1));
		$this->assertSame(303, $status, 'the login');
		$this->assertSame(0, $this->knownAddresses(), 'a correct password alone makes the address a known one');
		$this->assertSame(2, $this->unhandledFailedLogins(), 'a correct password alone forgets the failed logins');

		// the page which asks for the second factor
		list($status, $body) = $this->request('option=com_users&view=captive');
		$this->assertSame(200, $status);
		$this->assertStringContainsString('captive.validate', $body, 'Joomla asks for the second factor');
		$recordId = (int) $this->queryValue('SELECT id FROM #__user_mfa WHERE user_id='.$this->userId);
		return array('option' => 'com_users', 'task' => 'captive.validate', 'record_id' => $recordId,
			$this->formToken($body) => 1);
	}

	private static function wrongCode()
	{
		return self::totpCode() === '000000' ? '000001' : '000000';
	}

	public function testLoginIsASuccessOnlyOnceTheSecondFactorIsDone()
	{
		$validate = $this->loginWithPassword();

		// a wrong code, and the requests after it
		list($status) = $this->request('', $validate + array('code' => self::wrongCode()));
		$this->assertSame(303, $status);
		$this->request('option=com_users&view=captive&record_id='.$validate['record_id']);
		$this->assertSame(0, $this->knownAddresses(), 'a wrong second factor');
		$this->assertSame(3, $this->unhandledFailedLogins(), 'the wrong code is a failed login, the earlier ones are kept');

		// the right one: Joomla lets the user in with the request after it
		list($status) = $this->request('', $validate + array('code' => self::totpCode()));
		$this->assertSame(303, $status);
		list($status) = $this->request('');
		$this->assertSame(200, $status);
		$this->assertSame('Admin', $this->queryValue("SELECT username FROM #__bfstop_knownip WHERE ipaddress='127.0.0.1'"));
		$this->assertSame(0, $this->unhandledFailedLogins());
	}

	/**
	 * Somebody who has the password still has the code to guess: the wrong
	 * codes add to the failed passwords of the address (2, and the attempts
	 * allowed are 5), and the address is blocked - the right code is
	 * refused then.
	 */
	public function testWrongSecondFactorsBlockTheAddress()
	{
		$validate = $this->loginWithPassword();
		for ($i = 1; $i <= 3; ++$i)
		{
			$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_bannedip'), 'blocked before the attempts are used');
			list($status) = $this->request('', $validate + array('code' => self::wrongCode()));
			$this->assertSame(303, $status, 'wrong code '.$i);
		}
		$this->assertSame('127.0.0.1', $this->queryValue('SELECT ipaddress FROM #__bfstop_bannedip'));
		list($status) = $this->request('', $validate + array('code' => self::totpCode()));
		$this->assertSame(403, $status, 'the right code from a blocked address');
		$this->assertSame(0, $this->knownAddresses());
	}
}
