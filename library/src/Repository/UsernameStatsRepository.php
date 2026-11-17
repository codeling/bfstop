<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Repository;

defined('_JEXEC') or die;

use Joomla\Database\ParameterType;

/**
 * How many failed logins there were against each username (issue #136).
 * Unlike the failed login entries themselves, these statistics are not
 * removed by the automatic purge.
 */
class UsernameStatsRepository extends Repository
{
	private const Table = '#__bfstop_username_stats';

	// upper bound for the rows, which (unlike the failed logins) are not
	// purged by age: an attacker can make up as many usernames as they like
	public const MaxRows = 10000;

	/**
	 * Counts a failed login against $username. Fail-open: not counted.
	 */
	public function recordAttempt($username, $logtime)
	{
		$this->failOpen('recordAttempt', function () use ($username, $logtime)
		{
			$sql = 'INSERT INTO '.self::Table.
				' (username, attempts, first_attempt, last_attempt) VALUES (:username, 1, :first, :last)';
			// upsert: ON DUPLICATE KEY UPDATE is MySQL-only (issue #206)
			if ($this->db->getServerType() === 'postgresql')
			{
				$sql .= ' ON CONFLICT (username) DO UPDATE SET'.
					' attempts='.self::Table.'.attempts+1, last_attempt=:last2';
			}
			else
			{
				$sql .= ' ON DUPLICATE KEY UPDATE attempts=attempts+1, last_attempt=:last2';
			}
			$query = $this->db->createQuery();
			$query->setQuery($sql);
			$values = array('username' => (string) $username, 'first' => (string) $logtime,
				'last' => (string) $logtime, 'last2' => (string) $logtime);
			$this->execute($query, $values);
		}, null);
	}

	/**
	 * Keeps the statistics below $maxRows by deleting the entries of the
	 * usernames with the fewest attempts, the longest ago first. Fail-open:
	 * the next run does it.
	 */
	public function trim($maxRows = null)
	{
		$maxRows = $maxRows ?? self::MaxRows;
		$this->failOpen('trim', function () use ($maxRows)
		{
			$this->trimOldest(self::Table, 'username', 'attempts ASC, last_attempt ASC', $maxRows, 1000, ParameterType::STRING);
		}, null);
	}
}
