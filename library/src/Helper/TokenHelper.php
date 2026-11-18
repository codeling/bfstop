<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Helper;

defined('_JEXEC') or die;

use Joomla\CMS\Uri\Uri;

class TokenHelper
{
	/**
	 * 160 random bits as 40 hex digits. random_bytes() throws if the system
	 * has no source of randomness: better no token (the caller's exception
	 * handling) than a weak one.
	 */
	public static function getToken()
	{
		return bin2hex(random_bytes(20));
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
