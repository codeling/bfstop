<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Service;

defined('_JEXEC') or die;

use Joomla\CMS\Application\CMSApplicationInterface;
use Joomla\CMS\User\UserHelper;
use Joomla\Component\Users\Administrator\Helper\Mfa as MfaHelper;

/**
 * Holds back the successful login of a user with multi-factor authentication
 * (MFA) until the MFA is done (issue #342, finding 4).
 *
 * Joomla dispatches onUserLogin once the password (or another first factor)
 * is right: the user is logged in then, and the captive page which asks for
 * the second factor only comes with the requests after it
 * (MultiFactorAuthenticationHandler). A login which BFStop took for done at
 * that point would remember the address as one the user logs in from, and
 * forget the address's failed logins, on a correct password alone - the
 * very thing somebody with a stolen password has.
 *
 * So the plugin holds such a login back (hold(), in the session of the
 * client) and completes it (releaseIfChecked()) with the first request in
 * which Joomla says that the MFA is done: its session flag
 * "com_users.mfa_checked", set once the second factor was validated - and
 * also for a user who needs none. Whether MFA is due is Joomla's decision
 * (the user's groups, the methods which are active, the login being a
 * silent one, ...), which isn't repeated here: that flag is the only thing
 * of Joomla's internals this reads, and hasMfa() only decides which logins
 * to hold back, so that a change in Joomla can at worst affect the users
 * who have MFA. If Joomla stops setting the flag, such a login is never
 * completed: the address isn't remembered, which is the safe side.
 * MfaLoginHttpTest logs in with a second factor against the Joomla site of
 * every version of the matrix, which is what tells whether Joomla still sets
 * the flag as this expects (see tests/README.md).
 */
class MfaGate
{
	// what the session holds while a login is held back: a JSON string (the
	// session's registry would turn an array into something else), with the
	// username, the email address and the time of the login
	public const HeldKey = 'bfstop_held_login';

	// Joomla's flag: MFA has been checked in this session (see
	// MultiFactorAuthenticationHandler::needsMultiFactorAuthenticationRedirection())
	public const CheckedKey = 'com_users.mfa_checked';

	// a login held back this long ago isn't completed any more: the session
	// outlived it, or the user came back to it after a day
	public const MaxAgeSeconds = 86400;

	private CMSApplicationInterface $app;

	public function __construct(CMSApplicationInterface $app)
	{
		$this->app = $app;
	}

	/**
	 * The session of the client, if there is one to ask: the site and the
	 * backend have MFA; the API and the command line neither need a session
	 * nor have a user who is asked for a second factor.
	 */
	private function session()
	{
		if (!($this->app->isClient('site') || $this->app->isClient('administrator')) ||
			!method_exists($this->app, 'getSession'))
		{
			return null;
		}
		try
		{
			return $this->app->getSession();
		}
		catch (\Throwable $e)
		{
			return null;
		}
	}

	/**
	 * Whether the account $username has set up multi-factor authentication
	 * (of any method: whether it is asked for is up to Joomla, see the
	 * class). A user who has none, or who can't be found, or whose MFA
	 * records can't be read, doesn't have a login to hold back: it is
	 * completed as it always was.
	 *
	 * An account whose MFA Joomla would still have to migrate from its
	 * Joomla 3 settings has no record yet: its first login after the update
	 * is not held back.
	 */
	public function hasMfa(string $username): bool
	{
		if ($username === '' || $this->session() === null || !class_exists(MfaHelper::class))
		{
			return false;
		}
		try
		{
			$id = (int) UserHelper::getUserId($username);
			return $id > 0 && count(MfaHelper::getUserMfaRecords($id)) > 0;
		}
		catch (\Throwable $e)
		{
			return false;
		}
	}

	/**
	 * Holds back the login of $username (and $email, which the failed logins
	 * of the account may have been typed with). Replaces one held back
	 * before: it was another login of this client.
	 *
	 * @return bool whether it is held back; if not (no session to keep it
	 *              in), the caller completes it now
	 */
	public function hold(string $username, string $email): bool
	{
		$session = $this->session();
		if ($session === null)
		{
			return false;
		}
		try
		{
			$session->set(self::HeldKey, json_encode(array(
				'username' => $username, 'email' => $email, 'time' => time())));
			return true;
		}
		catch (\Throwable $e)
		{
			return false;
		}
	}

	/**
	 * Forgets a login held back, if there is one: a new login of this
	 * client supersedes it.
	 */
	public function discard(): void
	{
		$session = $this->session();
		if ($session === null)
		{
			return;
		}
		try
		{
			if ($session->isActive() && $session->has(self::HeldKey))
			{
				$session->clear(self::HeldKey);
			}
		}
		catch (\Throwable $e)
		{
			// nothing held back which could be completed
		}
	}

	/**
	 * The login which was held back, if Joomla says by now that its MFA is
	 * done and the user logged in is still the one it was for; null if there
	 * is none, or the MFA isn't done. A login released is not held any
	 * longer. Called for every request of a logged-in user, so it asks the
	 * database for nothing, and the session only if there is one already
	 * (a guest's request must not start one, a cached page would get a
	 * cookie).
	 *
	 * @return array{username: string, email: string}|null
	 */
	public function releaseIfChecked(): ?array
	{
		$identity = $this->app->getIdentity();
		if ($identity === null || $identity->guest)
		{
			return null;
		}
		$session = $this->session();
		try
		{
			if ($session === null || !$session->isActive() || !$session->has(self::HeldKey) ||
				!$session->get(self::CheckedKey))
			{
				return null;
			}
			$held = json_decode((string) $session->get(self::HeldKey), true);
			$session->clear(self::HeldKey);
		}
		catch (\Throwable $e)
		{
			return null;
		}
		if (!is_array($held) || !isset($held['username'], $held['time']) ||
			time() - (int) $held['time'] > self::MaxAgeSeconds ||
			strcasecmp((string) $identity->username, (string) $held['username']) !== 0)
		{
			return null;
		}
		return array('username' => (string) $held['username'], 'email' => (string) ($held['email'] ?? ''));
	}
}
