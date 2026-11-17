<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Service;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\LockHelper;
use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;

/**
 * Lets the logins of one address be handled one after the other.
 *
 * A failed login is only known - and counted - once Joomla has checked the
 * password, long after its request was let through as not blocked. Logins
 * sent at the same time would therefore all be let through and all get
 * their password checked, however few attempts are allowed: as many as the
 * server handles in parallel, with every burst. So a request which submits
 * a password waits (await()) until the one before it from the same address
 * has been counted (Bfstop::onUserLoginFailure()) or has succeeded
 * (Bfstop::onUserLogin()) - or has ended otherwise, the operating system
 * releases the lock then. After that, the caller looks at the block list
 * again.
 *
 * The turn lasts from the routing of the request to its login event, so one
 * object is kept for the whole request.
 */
class LoginTurn
{
	// the lock files: an address always gets the same one. Addresses which
	// share a file wait for each other's logins too (each at most
	// WaitSeconds), so when many addresses log in at once - an attack from
	// many - the more files, the less often a user's login waits for one of
	// them: with 100 such addresses about 1 in 11 does, with 64 files 4 in 5.
	// Each file is empty; it is created when first used and kept (deleting a
	// lock file which others may be waiting for is unsafe)
	public const Slots = 1024;

	// how long a login waits for those of its address before it; if they are
	// not done by then, it is handled alongside them
	public const WaitSeconds = 5;

	// the lock this request holds, see await()
	private $handle = null;

	/**
	 * The lock file for the logins of a client, by the key it is tracked
	 * under (IpHelper::trackedAddress()), one set of files per site (see
	 * Responder::delaySlotFiles()). A fixed number of files, not one per
	 * address: a visitor with many addresses must not be able to fill the
	 * directory. Which one an address gets depends on the site's secret, so
	 * nobody can pick addresses which share the file of somebody else's.
	 */
	public static function file($trackedAddress)
	{
		$app = Factory::getApplication();
		$slot = hexdec(substr(hash_hmac('sha256', (string) $trackedAddress, (string) $app->get('secret', '')), 0, 7))
			% self::Slots;
		return HtaccessHelper::lockDirectory().'/bfstop-login-'.LockHelper::siteHash().'-'.$slot.'.lock';
	}

	/**
	 * Waits for the turn of this request's login, see the class. The wait is
	 * limited (WaitSeconds), and without a lock file (no writable temporary
	 * directory) there is none: the login is handled as before then, it must
	 * never become impossible to log in.
	 *
	 * @param string $trackedAddress the key the client is tracked under
	 * @param string $ipAddress      its address, for the log
	 * @return bool whether the block list has to be looked at again
	 */
	public function await($trackedAddress, $ipAddress, LoggerHelper $logger): bool
	{
		if ($this->handle !== null)
		{
			return false;
		}
		$file = self::file($trackedAddress);
		$handle = LockHelper::acquire($file, self::WaitSeconds);
		if ($handle === false)
		{
			$logger->log('Could not create the lock file '.$file.
				': logins from the same address are not handled one at a time', Log::WARNING);
			return false;
		}
		if ($handle === null)
		{
			$logger->log('Login from '.$ipAddress.' waited '.self::WaitSeconds.
				's for other logins from this address, handling it alongside them', Log::INFO);
			return true;
		}
		$this->handle = $handle;
		return true;
	}

	/** Lets the next login of the address be handled. */
	public function end()
	{
		if ($this->handle !== null)
		{
			LockHelper::release($this->handle);
			$this->handle = null;
		}
	}
}
