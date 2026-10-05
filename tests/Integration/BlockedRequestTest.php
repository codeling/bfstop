<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
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
		$db = Factory::getDbo();
		$db->setQuery("SELECT params FROM #__extensions WHERE type='plugin' AND element='bfstop'");
		self::$originalParams = $db->loadResult();
	}

	public static function tearDownAfterClass(): void
	{
		if (self::$originalParams !== null)
		{
			$db = Factory::getDbo();
			$db->setQuery('UPDATE #__extensions SET params='.$db->quote(self::$originalParams).
				" WHERE type='plugin' AND element='bfstop'");
			$db->execute();
		}
	}

	private function configure(array $params = array())
	{
		$this->setPluginParams(json_encode($params + array(
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

	private function request($query = '', $ip = self::Ip, $routed = true)
	{
		$command = escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/fixtures/request.php').' '.
			escapeshellarg($ip).' '.escapeshellarg($query).($routed ? '' : ' --no-route').' 2>&1';
		exec($command, $output, $exitCode);
		$output = implode("\n", $output);
		$this->assertSame(0, $exitCode, $output);
		return $output;
	}

	private function assertBlocked($query = '', $ip = self::Ip)
	{
		$output = $this->request($query, $ip);
		$this->assertStringContainsString(self::BlockedMessage, $output, "request '$query' should be blocked");
		$this->assertStringNotContainsString('NOT BLOCKED', $output);
	}

	private function assertNotBlocked($query = '', $ip = self::Ip)
	{
		$output = $this->request($query, $ip);
		$this->assertStringContainsString('NOT BLOCKED', $output, "request '$query' should not be blocked");
		$this->assertStringNotContainsString(self::BlockedMessage, $output);
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
		// duration 0 = "forever"; 5 years is still within DatabaseHelper::$UNLIMITED_DURATION
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

	public function testPasswordRecoveryStaysReachable()
	{
		// a blocked legitimate user must still be able to reset their password
		$this->configure();
		$this->block();
		$this->assertNotBlocked('option=com_users&view=reset');
		$this->assertNotBlocked('option=com_users&view=remind');
		$this->assertBlocked('option=com_users&view=login');
	}

	public function testValidUnblockTokenGetsThrough()
	{
		$this->configure();
		$blockId = $this->block();
		$token = (new DatabaseHelper($this->logger))->getNewUnblockToken($blockId, str_repeat('ab', 20));
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
		$token = (new DatabaseHelper($this->logger))->getNewUnblockToken($blockId, str_repeat('ab', 20));
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
		$token = (new DatabaseHelper($this->logger))->getNewUnblockToken($otherBlockId, str_repeat('cd', 20));
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
}
