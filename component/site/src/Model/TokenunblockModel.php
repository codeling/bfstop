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
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Repository\BlockRepository;
use Codeling\Library\Bfstop\Repository\Repositories;
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

class TokenunblockModel extends BaseDatabaseModel
{
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

	private function repositories($logger): Repositories
	{
		return new Repositories($logger, $this->getDatabase());
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
	 * If that address can't be found, nothing is unblocked. (The view checks
	 * the form token of the POST before.)
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
		$repositories = $this->repositories($logger);
		$issued = $this->issuedFor($repositories, $token);
		if ($issued === null)
		{
			// no such token, no block for it (any more), or the tables can't
			// be read: without the block's address, the token can't be bound
			// to it - so it doesn't unblock anything
			$logger->log("com_bfstop-tokenunblock: No block found for the token.", Log::ERROR);
			return self::ResultNotFound;
		}
		if (!self::sameAddress($issued['address'], $requestIp))
		{
			$logger->log("com_bfstop-tokenunblock: Token used from an IP address ".
				"other than the blocked one.", Log::WARNING);
			return self::ResultWrongIp;
		}
		return $this->lift($repositories, $token, $issued['blockId'], $logger);
	}

	/**
	 * Unblocks with $token, from wherever (see process() for what a request
	 * of the page has to show first).
	 */
	public function unblock($token, $logger)
	{
		$repositories = $this->repositories($logger);
		$issued = $this->issuedFor($repositories, $token);
		if ($issued === null)
		{
			$logger->log("com_bfstop-tokenunblock: Token not found.", Log::ERROR);
			return false;
		}
		return $this->lift($repositories, $token, $issued['blockId'], $logger) === self::ResultUnblocked;
	}

	/**
	 * The block $token was issued for, see UnblockTokenRepository::issuedFor().
	 * The expired tokens are deleted first: a request of this page is where
	 * they are seen.
	 */
	private function issuedFor(Repositories $repositories, $token)
	{
		$repositories->unblockTokens()->purgeExpired();
		return $repositories->unblockTokens()->issuedFor($token);
	}

	/**
	 * Lifts the block $blockId which $token was issued for, and uses the
	 * token up. If the block can't be lifted, the token stays, so that the
	 * link can be tried again.
	 */
	private function lift(Repositories $repositories, $token, $blockId, $logger)
	{
		if (!$repositories->blocks()->lift(array($blockId), BlockRepository::LiftedByToken))
		{
			$logger->log("com_bfstop-tokenunblock: Could not unblock with the token.", Log::ERROR);
			return self::ResultFailed;
		}
		if (!$repositories->unblockTokens()->remove($token))
		{
			// the block is lifted all the same; the token expires
			$logger->log("com_bfstop-tokenunblock: Could not delete unblock_token.", Log::ERROR);
		}
		// with blocking through .htaccess, the web server would otherwise
		// go on rejecting the address until the plugin's next maintenance
		UnblockHelper::removeLiftedHtaccessBlocks($logger);
		$logger->log("com_bfstop-tokenunblock: Successfully unblocked with token.", Log::INFO);
		return self::ResultUnblocked;
	}
}
