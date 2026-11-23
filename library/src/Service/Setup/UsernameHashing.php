<?php
/*
 * @package BFStop Library (lib_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Service\Setup;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\RiskHelper;
use Codeling\Library\Bfstop\Helper\UsernameHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
use Joomla\Registry\Registry;

/**
 * Hashes the usernames 1.x stored in plain text (the update copied them into
 * the username statistics, which aren't purged by age): every name typed
 * into the login form, also passwords typed there by mistake. 2.0 hashes
 * new ones which belong to no account (see UsernameHelper), not the old
 * ones; this does, when the administrator asks for it (the setup
 * assistant's privacy step), in rounds which each take a bounded number of
 * names - of the failed logins first, then of the statistics. Names of
 * accounts and the common usernames of the settings stay readable, as for
 * new failed logins; two statistics which end up with the same hash are
 * merged.
 */
final class UsernameHashing
{
	public const FailedLogins = 'failedlogin';
	public const Statistics = 'stats';

	private Repositories $repositories;
	private Registry $settings;
	private string $secret;

	/**
	 * @param string $secret the site's secret, the key of the hash (see UsernameHelper)
	 */
	public function __construct(Repositories $repositories, Registry $settings, string $secret)
	{
		$this->repositories = $repositories;
		$this->settings = $settings;
		$this->secret = $secret;
	}

	/** Whether $username is a hash already (see UsernameHelper::forStorage()). */
	public static function isHashed(string $username): bool
	{
		return preg_match('/^\[unknown:[0-9a-f]{16}\]\z/', $username) === 1;
	}

	/**
	 * The hashes of those of $usernames which are to be hashed: no hash
	 * yet, no account's name or email address, no common username.
	 *
	 * @param string[] $usernames
	 * @return array<string, string> username => its hash
	 */
	public function hashesOf(array $usernames): array
	{
		$candidates = array_values(array_filter($usernames, fn ($name) => !self::isHashed((string) $name) &&
			!RiskHelper::isCommonUsername($this->settings, (string) $name)));
		$accounts = array_flip(array_map('mb_strtolower', $this->repositories->users()->existingLogins($candidates)));
		$hashes = array();
		foreach ($candidates as $name)
		{
			if (!isset($accounts[mb_strtolower((string) $name)]))
			{
				$hashes[(string) $name] = UsernameHelper::forStorage((string) $name, UsernameHelper::ModeHash, false, $this->secret);
			}
		}
		return $hashes;
	}

	/**
	 * One round: up to $limit usernames of the table $table (FailedLogins or
	 * Statistics) after $after, hashed where they are to be.
	 *
	 * @return array{last: string|null, hashed: int} last: the username to go
	 *         on after, null if the table is done
	 */
	public function round(string $table, string $after, int $limit = 200): array
	{
		$names = $table === self::FailedLogins
			? $this->repositories->failedLogins()->usernamesAfter($after, $limit)
			: $this->repositories->usernameStats()->usernamesAfter($after, $limit);
		$hashes = $this->hashesOf($names);
		foreach ($hashes as $name => $hash)
		{
			if ($table === self::FailedLogins)
			{
				$this->repositories->failedLogins()->renameUsername($name, $hash);
			}
			else
			{
				$this->repositories->usernameStats()->rename($name, $hash);
			}
		}
		return array('last' => count($names) < $limit ? null : (string) end($names), 'hashed' => count($hashes));
	}
}
