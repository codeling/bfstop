<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Service;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Repository\Repositories;

/**
 * What the plugin does with a login, put together from the tables it
 * touches.
 */
class LoginService
{
	private Repositories $repositories;

	public function __construct(Repositories $repositories)
	{
		$this->repositories = $repositories;
	}

	/**
	 * Records a failed login (an object with the columns of the table of
	 * failed logins): the entry, and the count against its username.
	 */
	public function recordFailedLogin($logEntry)
	{
		$this->repositories->failedLogins()->add($logEntry);
		$this->repositories->usernameStats()->recordAttempt($logEntry->username, $logEntry->logtime);
	}

	/**
	 * Records a successful login: the failed logins of the client which
	 * were counted against the user stop counting, and the address is one
	 * the user has logged in from.
	 *
	 * @param object      $info           ipaddress (the client's address) and username
	 * @param string|null $trackedAddress the key this client is tracked by (see
	 *                                    IpHelper::trackedAddress(): for IPv6 its
	 *                                    network), if not its address. Failed
	 *                                    logins are recorded under this key
	 * @param string|null $trustedAddress the key under which the login is
	 *                                    remembered as one the user has made
	 *                                    from here (IpHelper::trustPrefixLength():
	 *                                    never coarser than a /64), if not
	 *                                    $trackedAddress
	 */
	public function recordSuccessfulLogin($info, $trackedAddress = null, $trustedAddress = null)
	{
		$key = $trackedAddress ?? $info->ipaddress;
		$this->repositories->failedLogins()->markHandled($key, $info->username);
		$this->repositories->knownIps()->remember($trustedAddress ?? $key, $info->username);
	}

	/**
	 * Whether the failed logins which count towards blocking $ipaddress (those
	 * within $interval minutes before $logtime that haven't been handled yet)
	 * include attempts against an existing account other than $username.
	 * Attempts against usernames which don't exist don't count: they can't
	 * get an attacker anywhere. If that can't be determined, it is assumed
	 * that there are (fail-closed: no unblock link goes out then).
	 */
	public function hasFailedLoginsForOtherAccounts($interval, $ipaddress, $username, $logtime)
	{
		$attempted = $this->repositories->failedLogins()
			->unhandledUsernamesFromAddress($interval, $ipaddress, $logtime);
		if ($attempted === null)
		{
			return true;
		}
		$others = array_filter($attempted, function ($name) use ($username)
		{
			return mb_strtolower($name) !== mb_strtolower($username);
		});
		return count($others) > 0 && $this->repositories->users()->anyAccountExists($others);
	}
}
