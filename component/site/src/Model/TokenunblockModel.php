<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Site\Model;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\UnblockHelper;
use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

class TokenunblockModel extends BaseDatabaseModel
{
	// must stay in sync with the plugin's DatabaseHelper::$UNBLOCK_TOKEN_VALID_DAYS
	const TokenValidDays = 3;

	// outcomes of process()
	const ResultInvalid = 'invalid';
	const ResultConfirm = 'confirm';
	const ResultWrongIp = 'wrongip';
	const ResultUnblocked = 'unblocked';
	// no such token (it never existed, expired or was used already)
	const ResultNotFound = 'notfound';
	// the token exists, but unblocking failed (database error)
	const ResultFailed = 'failed';

	/**
	 * The HTTP status to answer an outcome of process() with. A GET request
	 * for a link only asks for confirmation whatever the token is (which keeps
	 * mail scanners and link previews, which open every link, from learning
	 * anything and from marking links as dead), so it is a 200, as is success.
	 */
	public static function httpStatus($result)
	{
		switch ($result)
		{
			case self::ResultInvalid:
				return 400;
			case self::ResultWrongIp:
				return 403;
			case self::ResultNotFound:
				return 404;
			case self::ResultFailed:
				return 500;
			default:
				return 200;
		}
	}

	/**
	 * The IP address the block belongs to which the token was issued for, or
	 * null if there is no such token.
	 */
	private function getBlockedIp($token)
	{
		try
		{
			$db = $this->getDatabase();
			$db->setQuery('SELECT b.ipaddress FROM #__bfstop_unblock_token t '.
				'INNER JOIN #__bfstop_bannedip b ON b.id = t.block_id '.
				'WHERE t.token='.$db->quote(DatabaseHelper::hashToken($token)));
			$ip = $db->loadResult();
			return ($ip === null || $ip === false) ? null : (string) $ip;
		}
		catch (\RuntimeException $e)
		{
			return null;
		}
	}

	// $blocked is an address, or a network in CIDR notation for clients which
	// are tracked (and blocked) by their IPv6 network
	private static function sameAddress($blocked, $address)
	{
		if (strpos($blocked, '/') !== false)
		{
			return IpHelper::isInSubnet($address, $blocked);
		}
		$binA = @inet_pton((string) $blocked);
		return $binA !== false && $binA === @inet_pton((string) $address);
	}

	/**
	 * Handles a request to the unblock page.
	 *
	 * Opening the link from the email (a GET request) must not unblock
	 * anything by itself: mail security scanners and link previews open every
	 * link in a message, which would let anyone who triggers an unblock email
	 * (by failing logins for a user whose mailbox is scanned) get unblocked
	 * again automatically. So a GET only asks for confirmation; the actual
	 * unblock needs a POST. In addition, the token only unblocks from the IP
	 * address it was issued for - the one that got blocked - so a scanner or
	 * anyone else to whom the link was forwarded can't use it from elsewhere.
	 *
	 * @return string one of the Result* constants
	 */
	public function process($token, $isPost, $requestIp, $logger)
	{
		if ($token === '')
		{
			return self::ResultInvalid;
		}
		if (!$isPost)
		{
			return self::ResultConfirm;
		}
		$blockedIp = $this->getBlockedIp($token);
		if ($blockedIp !== null && !self::sameAddress($blockedIp, $requestIp))
		{
			$logger->log("com_bfstop-tokenunblock: Token used from an IP address ".
				"other than the blocked one.", Log::WARNING);
			return self::ResultWrongIp;
		}
		return $this->unblockWithResult($token, $logger);
	}

	public function unblock($token, $logger)
	{
		return $this->unblockWithResult($token, $logger) === self::ResultUnblocked;
	}

	private function unblockWithResult($token, $logger)
	{
		$db = $this->getDatabase();
		// prune old tokens:
		try
		{
			// cutoff computed in PHP, as DATE_ADD is MySQL-only (issue bfstop#206)
			$db->setQuery('DELETE FROM #__bfstop_unblock_token '.
				'WHERE crdate < '.
				$db->quote(date('Y-m-d H:i:s', time() - self::TokenValidDays * 86400)));
			$db->execute();
			// get token:
			// only the hash of a token is stored, see DatabaseHelper::hashToken()
			$stored = DatabaseHelper::hashToken($token);
			$db->setQuery('SELECT * FROM #__bfstop_unblock_token WHERE token='.
				$db->quote($stored));
			$unblockTokenEntry = $db->loadObject();
			if ($unblockTokenEntry == null)
			{
				$logger->log("com_bfstop-tokenunblock: Token not found.", Log::ERROR);
				return self::ResultNotFound;
			}
			UnblockHelper::unblockDB($db, array($unblockTokenEntry->block_id), 1, $logger);
			$sql = 'DELETE FROM #__bfstop_unblock_token WHERE token='.
					$db->quote($stored);
			$db->setQuery($sql);
			$success = $db->execute();
		}
		catch (\RuntimeException $e)
		{
			$success = false;
			$logger->log($e->getMessage(), Log::ERROR);
		}
		if (!$success)
		{
			$logger->log("com_bfstop-tokenunblock: Could not delete unblock_token.", Log::ERROR);
		}
		else
		{
			$logger->log("com_bfstop-tokenunblock: Successfully unblocked with token.", Log::INFO);
		}
		return $success ? self::ResultUnblocked : self::ResultFailed;
	}
}
