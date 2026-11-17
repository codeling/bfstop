<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Helper;

defined('_JEXEC') or die;

use Joomla\CMS\Log\Log;
use Joomla\CMS\Uri\Uri;

class TokenHelper
{
	public const HexLetter = '0123456789abcdef';

	private static function getRandHexLetter()
	{
		$idx = random_int(0, 15);
		return substr(self::HexLetter, $idx, 1);
	}

	private static function getRandToken($length)
	{
		$token = '';
		for ($i = 0; $i < $length; ++$i)
		{
			$token .= self::getRandHexLetter();
		}
		return $token;
	}

	public static function getToken(LoggerHelper $logger)
	{
		$length = 64;
		try
		{
			$token = random_bytes($length);
			$logger->log('Using PHP random_bytes() for token', Log::DEBUG);
		}
		catch (\Exception $e)
		{
			$logger->log('random_bytes() failed ('.$e->getMessage().'), falling back to a less strong token generator!', Log::WARNING);
			$token = self::getRandToken($length);
		}
		return sha1($token);
	}

	/**
	 * The link to the unblock page, which is a page of the site: Uri::root()
	 * is the site's address in every application (Uri::base() is the
	 * backend's in the backend, and the API's in the API). Like any address
	 * Joomla builds, it has the host the request was sent to unless the
	 * site's $live_site is set.
	 */
	public static function unblockLink($token)
	{
		return Uri::root().'index.php?option=com_bfstop&view=tokenunblock&token='.rawurlencode((string) $token);
	}
}
