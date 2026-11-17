<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

/**
 * What of a failed login's username field gets stored.
 *
 * Users regularly type their password into the username field. Storing it
 * verbatim would keep those passwords in the failed login table and the
 * per-username statistics (which are not purged automatically), show them
 * in the backend and mail them to the administrators. So by default only
 * usernames that are not a secret in the first place - existing accounts
 * and the well-known names an admin configured as "common usernames" - are
 * stored readably; any other value is replaced by a keyed hash. The hash is
 * still the same for the same input, so attempts against one unknown name
 * are still counted together (e.g. for the account throttle and the
 * username statistics), but the input cannot be read back from it.
 */
class UsernameHelper
{
	public const ModeHash = 'hash';
	public const ModePlain = 'plain';

	/**
	 * @param string $username      the username as entered
	 * @param string $mode          ModeHash or ModePlain
	 * @param bool   $isReadable    whether this username may be stored as is
	 *                              (existing account, common username)
	 * @param string $secret        site-specific key for the hash
	 */
	public static function forStorage($username, $mode, $isReadable, $secret)
	{
		if ($mode === self::ModePlain || $isReadable)
		{
			return $username;
		}
		return '[unknown:'.
			substr(hash_hmac('sha256', mb_strtolower($username), (string) $secret), 0, 16).
			']';
	}
}
