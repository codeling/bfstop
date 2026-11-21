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
 * The failed logins (#__bfstop_failedlogin). An entry is "handled" once it
 * has led to a block, or the user has logged in successfully: it doesn't
 * count towards blocking then.
 */
class FailedLoginRepository extends Repository
{
	private const Table = '#__bfstop_failedlogin';

	// upper bound for the rows, however the purge age is set: a visitor can
	// add one for every request, from as many addresses as they like
	public const MaxRows = 200000;

	/** the columns a failed login is added with (see add()) */
	private const Columns = array('ipaddress', 'logtime', 'username', 'origin', 'handled');

	/**
	 * Adds a failed login (an object with the columns of the table); gives it
	 * its id.
	 *
	 * Fail-open: a failed login which can't be stored isn't counted - better
	 * than answering the visitor's request with an error. The failure is
	 * logged, and counted by FailurePolicy.
	 */
	public function add($logEntry)
	{
		$this->failOpen('add', function () use ($logEntry)
		{
			$logEntry->id = $this->insert(self::Table,
				array_intersect_key(get_object_vars($logEntry), array_flip(self::Columns)), 'id');
		}, null);
	}

	/**
	 * The failed logins from $ipaddress in the $minutes up to $time which
	 * haven't been handled. Fail-open: 0.
	 */
	public function countUnhandledFromAddress($minutes, $ipaddress, $time)
	{
		return $this->failOpen('countUnhandledFromAddress', function () use ($minutes, $ipaddress, $time)
		{
			$values = array();
			$query = $this->windowQuery(self::Table, 'logtime', $time, $minutes, $values)
				->where($this->db->quoteName('ipaddress').' = :ip')
				->where($this->db->quoteName('handled').' = 0');
			$values['ip'] = (string) $ipaddress;
			return $this->count($query, $values);
		}, 0);
	}

	/**
	 * The failed logins against $username in the $minutes up to $time which
	 * haven't been handled, from whatever address: a distributed attack
	 * spreading its attempts over many addresses against one account is still
	 * caught (issue #76, OWASP guidance on account-scoped lockout counters).
	 * Fail-open: 0.
	 */
	public function countUnhandledForUsername($minutes, $username, $time)
	{
		return $this->failOpen('countUnhandledForUsername', function () use ($minutes, $username, $time)
		{
			$values = array();
			$query = $this->windowQuery(self::Table, 'logtime', $time, $minutes, $values)
				->where($this->db->quoteName('username').' = :username')
				->where($this->db->quoteName('handled').' = 0');
			$values['username'] = (string) $username;
			return $this->count($query, $values);
		}, 0);
	}

	/**
	 * All failed logins in the $minutes up to $time, whoever they are from
	 * (to limit the number of notifications). Fail-open: 0.
	 */
	public function countInWindow($time, $minutes)
	{
		return $this->failOpen('countInWindow', function () use ($time, $minutes)
		{
			$values = array();
			$query = $this->windowQuery(self::Table, 'logtime', $time, $minutes, $values);
			return $this->count($query, $values);
		}, 0);
	}

	/**
	 * The failed logins of the last hour. Fail-open: 0.
	 */
	public function countInLastHour()
	{
		return $this->failOpen('countInLastHour', function ()
		{
			$query = $this->db->createQuery()
				->select('COUNT(*)')
				->from($this->db->quoteName(self::Table))
				->where($this->db->quoteName('logtime').' > :from');
			$values = array('from' => self::minutesBefore(self::now(), 60));
			return $this->count($query, $values);
		}, 0);
	}

	// the most failed logins listUnhandledFromAddress() reads: those which
	// count towards a block are about the block threshold (at most 25)
	private const ListLimit = 100;

	/**
	 * The failed logins from $ipaddress in the $minutes up to $time which
	 * haven't been handled - those countUnhandledFromAddress() counts -
	 * oldest first, at most ListLimit (the latest). Fail-open: none.
	 *
	 * @return object[]
	 */
	public function listUnhandledFromAddress($minutes, $ipaddress, $time)
	{
		return $this->failOpen('listUnhandledFromAddress', function () use ($minutes, $ipaddress, $time)
		{
			$values = array();
			$query = $this->windowQuery(self::Table, 'logtime', $time, $minutes, $values)
				->clear('select')
				->select($this->db->quoteName(array('id', 'ipaddress', 'logtime', 'username', 'origin')))
				->where($this->db->quoteName('ipaddress').' = :ip')
				->where($this->db->quoteName('handled').' = 0')
				->order($this->db->quoteName('logtime').' DESC, '.$this->db->quoteName('id').' DESC');
			$values['ip'] = (string) $ipaddress;
			return array_reverse($this->objects($query, $values, 0, self::ListLimit));
		}, array());
	}

	/**
	 * The usernames the unhandled failed logins from $ipaddress in the
	 * $minutes up to $time were against. Unknown (null) if they can't be
	 * read.
	 *
	 * @return string[]|null
	 */
	public function unhandledUsernamesFromAddress($minutes, $ipaddress, $time)
	{
		return $this->unknown('unhandledUsernamesFromAddress', function () use ($minutes, $ipaddress, $time)
		{
			$values = array();
			$query = $this->windowQuery(self::Table, 'logtime', $time, $minutes, $values)
				->clear('select')
				->select('DISTINCT '.$this->db->quoteName('username'))
				->where($this->db->quoteName('ipaddress').' = :ip')
				->where($this->db->quoteName('handled').' = 0');
			$values['ip'] = (string) $ipaddress;
			return $this->column($query, $values);
		});
	}

	/**
	 * Marks the unhandled failed logins from $ipaddress - and, with
	 * $usernames (a username, or several: an account's username and email
	 * address), only those against them, whatever their case, as Joomla
	 * matches a login - as handled. Fail-open: they go on counting.
	 *
	 * @param string|string[]|null $usernames
	 */
	public function markHandled($ipaddress, $usernames = null)
	{
		$this->failOpen('markHandled', function () use ($ipaddress, $usernames)
		{
			$query = $this->db->createQuery()
				->update($this->db->quoteName(self::Table))
				->set($this->db->quoteName('handled').' = 1')
				->where($this->db->quoteName('ipaddress').' = :ip')
				->where($this->db->quoteName('handled').' = 0');
			$values = array('ip' => (string) $ipaddress);
			if ($usernames !== null)
			{
				$names = array_values(array_unique(array_filter(array_map('strval', (array) $usernames),
					fn ($name) => $name !== '')));
				if (count($names) === 0)
				{
					return;
				}
				// MySQL and MariaDB compare the column case-insensitively
				// themselves (its collation); PostgreSQL exactly. The rows are
				// found by the address, so LOWER() reads no more of them
				$lower = $this->db->getServerType() === 'postgresql';
				$column = $this->db->quoteName('username');
				$placeholders = array();
				foreach ($names as $i => $name)
				{
					$values['username'.$i] = $name;
					$placeholders[] = $lower ? 'LOWER(:username'.$i.')' : ':username'.$i;
				}
				$query->where(($lower ? 'LOWER('.$column.')' : $column).' IN ('.implode(', ', $placeholders).')');
			}
			$this->execute($query, $values);
		}, null);
	}

	/**
	 * Deletes the failed logins from before $date. Fail-open: the next run
	 * does it.
	 */
	public function purgeBefore($date)
	{
		$this->failOpen('purgeBefore', function () use ($date)
		{
			$this->deleteBefore(self::Table, 'logtime', $date);
		}, null);
	}

	/**
	 * Keeps the failed logins below $maxRows by deleting the oldest ones.
	 * Fail-open: the next run does it.
	 */
	public function trim($maxRows = null)
	{
		$maxRows = $maxRows ?? self::MaxRows;
		$this->failOpen('trim', function () use ($maxRows)
		{
			$this->trimOldest(self::Table, 'id', 'id ASC', $maxRows, 5000, ParameterType::INTEGER);
		}, null);
	}
}
