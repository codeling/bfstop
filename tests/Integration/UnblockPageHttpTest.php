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
 * The unblock page of the component as a visitor gets it: the status and the
 * headers of the response can't be observed from within a PHP CLI process, so
 * PHP's built-in web server runs the Joomla site and the requests are real
 * HTTP requests (from 127.0.0.1). Unlike the other tests, this runs the
 * plugin and the component as installed in the Joomla site, not the source
 * checkouts.
 */
class UnblockPageHttpTest extends IntegrationTestCase
{
	private const Query = 'option=com_bfstop&view=tokenunblock';

	private static $originalParams;
	private $server;
	private $port;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		if (!getenv('COM_BFSTOP_ROOT'))
		{
			self::markTestSkipped('COM_BFSTOP_ROOT not set, see tests/README.md');
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
		$this->configure();
		$listener = stream_socket_server('tcp://127.0.0.1:0');
		$this->port = (int) substr(strrchr(stream_socket_get_name($listener, false), ':'), 1);
		fclose($listener);
		// exec: the shell must be replaced by the server, or terminating the
		// process in tearDown() would leave the server running
		$this->server = proc_open('exec '.escapeshellarg(PHP_BINARY).' -S 127.0.0.1:'.$this->port.' -t '.
			escapeshellarg(getenv('JOOMLA_ROOT')), array(0 => array('file', '/dev/null', 'r'),
			1 => array('file', '/dev/null', 'w'), 2 => array('file', '/dev/null', 'w')), $pipes);
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

	private function configure(array $params = array())
	{
		$this->setPluginParams(json_encode($params + array('blockMode' => 'full', 'logLevel' => 8)));
	}

	/** @return array [status, lower-cased headers, body] */
	private function request($method, $query, $post = '')
	{
		$context = stream_context_create(array('http' => array('method' => $method, 'ignore_errors' => true,
			'follow_location' => 0, 'content' => $post,
			'header' => $method === 'POST' ? 'Content-Type: application/x-www-form-urlencoded' : '')));
		$body = file_get_contents('http://127.0.0.1:'.$this->port.'/index.php?'.$query, false, $context);
		$headers = array();
		foreach ($http_response_header as $line)
		{
			if (preg_match('#^HTTP/\S+ (\d+)#', $line, $m))
			{
				$status = (int) $m[1];
			}
			elseif (strpos($line, ':') !== false)
			{
				list($name, $value) = explode(':', $line, 2);
				$headers[strtolower($name)][] = trim($value);
			}
		}
		return array($status, $headers, $body);
	}

	private function token($token, $blockedIp = '203.0.113.9')
	{
		$blockId = $this->insert('#__bfstop_bannedip', array('ipaddress' => $blockedIp,
			'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		$this->insert('#__bfstop_unblock_token', array('token' => $token, 'block_id' => $blockId, 'crdate' => self::minutesAgo(1)));
		return $blockId;
	}

	private function tokenCount()
	{
		return (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock_token');
	}

	public function testLinkWithoutTokenIsABadRequest()
	{
		list($status, , $body) = $this->request('GET', self::Query);
		$this->assertSame(400, $status);
		$this->assertStringContainsString('Invalid call', $body);
	}

	public function testOpeningTheLinkAsksForConfirmationWhateverTheToken()
	{
		$this->token('realtoken');
		foreach (array('realtoken', 'unknowntoken') as $token)
		{
			list($status, , $body) = $this->request('GET', self::Query.'&token='.$token);
			$this->assertSame(200, $status, $token);
			$this->assertStringContainsString('Unblock my IP address', $body);
		}
		$this->assertSame(1, $this->tokenCount(), 'nothing was used up');
	}

	public function testWrongIpAddressIsForbidden()
	{
		$this->token('realtoken', '203.0.113.9'); // the request comes from 127.0.0.1
		list($status, , $body) = $this->request('POST', self::Query, 'token=realtoken');
		$this->assertSame(403, $status);
		$this->assertStringContainsString('only unblock the IP address it was issued for', $body, 'the message is still shown');
		$this->assertSame(1, $this->tokenCount());
	}

	public function testUnknownTokenIsNotFound()
	{
		list($status, , $body) = $this->request('POST', self::Query, 'token=unknowntoken');
		$this->assertSame(404, $status);
		$this->assertStringContainsString('Could not unblock', $body);
	}

	public function testUnblockSucceeds()
	{
		$blockId = $this->token('realtoken', '127.0.0.1');
		list($status, , $body) = $this->request('POST', self::Query, 'token=realtoken');
		$this->assertSame(200, $status);
		$this->assertStringContainsString('Successfully unblocked', $body);
		$this->assertSame(0, $this->tokenCount());
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock WHERE block_id='.$blockId));
		// and using the link again finds nothing
		list($status) = $this->request('POST', self::Query, 'token=realtoken');
		$this->assertSame(404, $status);
	}

	public function testErrorStatusesFollowTheUseHttpErrorSetting()
	{
		$this->configure(array('useHttpError' => 0));
		$this->token('realtoken', '203.0.113.9');
		foreach (array(array('GET', self::Query, ''), array('POST', self::Query, 'token=unknowntoken'),
			array('POST', self::Query, 'token=realtoken')) as $request)
		{
			list($status, , $body) = $this->request(...$request);
			$this->assertSame(200, $status, 'the message must reach the user: '.implode(' ', $request));
			$this->assertNotSame('', trim(strip_tags($body)));
		}
	}

	public function testTheLinkIsKeptSecret()
	{
		$this->token('realtoken');
		foreach (array(array('GET', self::Query.'&token=realtoken', ''), array('POST', self::Query, 'token=unknowntoken')) as $request)
		{
			list(, $headers) = $this->request(...$request);
			$this->assertStringContainsString('no-store', implode(',', $headers['cache-control'] ?? array()), 'not cached');
			$this->assertSame(array('no-referrer'), $headers['referrer-policy'] ?? null);
			$this->assertSame(array('noindex, nofollow'), $headers['x-robots-tag'] ?? null);
		}
	}
}
