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
 * The results of reverse-DNS lookups (#__bfstop_dnscache): the (potentially
 * slow) lookup is made at most once per address in a time window, see
 * issue #103.
 */
class DnsCacheRepository extends Repository
{
	private const Table = '#__bfstop_dnscache';

	// how long a result is trusted before the lookup is redone: keeps the
	// (potentially slow) gethostbyaddr() call to at most once per address and
	// window, see issue #103
	public const TtlDays = 7;
	// upper bound for the rows: there is one per address, and a client with
	// an IPv6 network can fail every login from another one
	public const MaxRows = 10000;

	/**
	 * Returns false if there is no (unexpired) cached entry for this IP - the
	 * caller should do a live lookup and cache it via put(). Returns null if
	 * the cache confirms this IP has no PTR record, or the cached hostname
	 * string otherwise. false/null/string are deliberately distinct: null
	 * must not be confused with "not cached".
	 *
	 * Fail-open: not cached (the lookup is made again).
	 *
	 * @param int $ttlDays how long a result is trusted
	 * @return string|false|null
	 */
	public function get($ipaddress, $ttlDays = self::TtlDays)
	{
		return $this->failOpen('get', function () use ($ipaddress, $ttlDays)
		{
			$query = $this->db->createQuery()
				->select($this->db->quoteName(array('hostname', 'checked_at')))
				->from($this->db->quoteName(self::Table))
				->where($this->db->quoteName('ipaddress').' = :ip');
			$values = array('ip' => (string) $ipaddress);
			$row = $this->row($query, $values);
			if ($row === null)
			{
				return false;
			}
			$checkedAt = strtotime($row['checked_at']);
			if ($checkedAt === false || (time() - $checkedAt) > ($ttlDays * 86400))
			{
				return false;
			}
			return $row['hostname'];
		}, false);
	}

	/**
	 * Remembers the result of a lookup ($hostname null: there is no PTR
	 * record). Fail-open: not remembered.
	 */
	public function put($ipaddress, $hostname)
	{
		$this->failOpen('put', function () use ($ipaddress, $hostname)
		{
			$now = self::now();
			$query = $this->db->createQuery()
				->select($this->db->quoteName('ipaddress'))
				->from($this->db->quoteName(self::Table))
				->where($this->db->quoteName('ipaddress').' = :ip');
			$values = array('ip' => (string) $ipaddress);
			if ($this->scalar($query, $values))
			{
				$update = $this->db->createQuery()
					->update($this->db->quoteName(self::Table))
					->set($this->db->quoteName('hostname').' = :hostname')
					->set($this->db->quoteName('checked_at').' = :now')
					->where($this->db->quoteName('ipaddress').' = :ip');
				$hostnameValue = $hostname === null ? null : (string) $hostname;
				$updateValues = array('now' => $now, 'ip' => (string) $ipaddress);
				$update->bind(':hostname', $hostnameValue, $hostnameValue === null ? ParameterType::NULL : ParameterType::STRING);
				$this->execute($update, $updateValues);
			}
			else
			{
				$entry = new \stdClass();
				$entry->ipaddress = $ipaddress;
				$entry->hostname = $hostname;
				$entry->checked_at = $now;
				$this->db->insertObject(self::Table, $entry);
			}
		}, null);
	}

	/**
	 * Deletes the cached results which have expired - nothing reads them any
	 * more - and, oldest first, as many more as needed to keep at most
	 * $maxRows. Fail-open: the next run does it.
	 */
	public function prune($ttlDays = null, $maxRows = null)
	{
		$ttlDays = $ttlDays ?? self::TtlDays;
		$maxRows = $maxRows ?? self::MaxRows;
		$this->failOpen('prune', function () use ($ttlDays, $maxRows)
		{
			$this->deleteBefore(self::Table, 'checked_at', self::daysAgo($ttlDays));
			$this->trimOldest(self::Table, 'ipaddress', 'checked_at ASC', $maxRows, 1000, ParameterType::STRING);
		}, null);
	}
}
