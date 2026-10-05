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
	const ResultFailed = 'failed';

	/**
	 * The IP address the block belongs to which the token was issued for, or
	 * null if there is no such token.
	 */
	private function getBlockedIp($token)
	{
		try
		{
			$this->_db->setQuery('SELECT b.ipaddress FROM #__bfstop_unblock_token t '.
				'INNER JOIN #__bfstop_bannedip b ON b.id = t.block_id '.
				'WHERE t.token='.$this->_db->quote($token));
			$ip = $this->_db->loadResult();
			return ($ip === null || $ip === false) ? null : (string) $ip;
		}
		catch (\RuntimeException $e)
		{
			return null;
		}
	}

	private static function sameAddress($a, $b)
	{
		$binA = @inet_pton((string) $a);
		return $binA !== false && $binA === @inet_pton((string) $b);
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
		return $this->unblock($token, $logger)
			? self::ResultUnblocked
			: self::ResultFailed;
	}

	public function unblock($token, $logger)
	{
		// prune old tokens:
		try
		{
			// cutoff computed in PHP, as DATE_ADD is MySQL-only (issue bfstop#206)
			$this->_db->setQuery('DELETE FROM #__bfstop_unblock_token '.
				'WHERE crdate < '.
				$this->_db->quote(date('Y-m-d H:i:s', time() - self::TokenValidDays * 86400)));
			$this->_db->execute();
			// get token:
			$this->_db->setQuery('SELECT * FROM #__bfstop_unblock_token WHERE token='.
				$this->_db->quote($token));
			$unblockTokenEntry = $this->_db->loadObject();
			if ($unblockTokenEntry == null)
			{
				$logger->log("com_bfstop-tokenunblock: Token not found.", Log::ERROR);
				return false;
			}
			UnblockHelper::unblockDB($this->_db, array($unblockTokenEntry->block_id), 1, $logger);
			$sql = 'DELETE FROM #__bfstop_unblock_token WHERE token='.
					$this->_db->quote($token);
			$this->_db->setQuery($sql);
			$success = $this->_db->execute();
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
		return $success;
	}
}
