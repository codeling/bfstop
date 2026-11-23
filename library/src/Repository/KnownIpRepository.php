<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Repository;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\IpHelper;
use Joomla\Database\ParameterType;

/**
 * The addresses users have logged in from (#__bfstop_knownip), under the key
 * a client is trusted by (see IpHelper::trustPrefixLength()).
 */
class KnownIpRepository extends Repository
{
	private const Table = '#__bfstop_knownip';

	// addresses are forgotten after this long without a login from them, and
	// the table is kept below this number of rows, oldest first: a visitor
	// with an account can log in from as many addresses as they like
	public const MaxAgeDays = 365;
	public const MaxRows = 100000;

	/**
	 * Remembers that $username has logged in from $key (an IPv4 address, or
	 * an IPv6 network, see IpHelper::trackedAddress()).
	 *
	 * Fail-open: not remembered, so the next login from there doesn't count
	 * as one from a known address.
	 */
	public function remember($key, $username)
	{
		$this->failOpen('remember', function () use ($key, $username)
		{
			$now = self::now();
			$query = $this->db->createQuery()
				->select($this->db->quoteName('id'))
				->from($this->db->quoteName(self::Table))
				->where($this->db->quoteName('ipaddress').' = :ip')
				->where($this->usernameMatches('username'));
			$values = array('ip' => (string) $key, 'username' => (string) $username);
			$id = $this->scalar($query, $values);
			if ($id)
			{
				$update = $this->db->createQuery()
					->update($this->db->quoteName(self::Table))
					->set($this->db->quoteName('last_success').' = :now')
					->where($this->db->quoteName('id').' = :id');
				$updateValues = array('now' => $now, 'id' => (int) $id);
				$this->execute($update, $updateValues);
			}
			else
			{
				// two logins at the same time may both have found none: the
				// second one updates the row of the first (the unique key is
				// the address and the username as it is spelt)
				$sql = 'INSERT INTO '.$this->db->quoteName(self::Table).
					' (ipaddress, username, first_success, last_success) VALUES (:ip, :username, :first, :last)';
				$sql .= $this->db->getServerType() === 'postgresql'
					? ' ON CONFLICT (ipaddress, username) DO UPDATE SET last_success = :last2'
					: ' ON DUPLICATE KEY UPDATE last_success = :last2';
				$insert = $this->db->createQuery();
				$insert->setQuery($sql);
				$insertValues = array('ip' => (string) $key, 'username' => (string) $username, 'first' => $now,
					'last' => $now, 'last2' => $now);
				$this->execute($insert, $insertValues);
			}
		}, null);
	}

	/**
	 * Whether $username has logged in successfully from $ipaddress before.
	 *
	 * Logins are remembered under the key the client is trusted by: an IPv4
	 * address itself, an IPv6 address by its network (never coarser than a
	 * /64, see IpHelper::TrustPrefixLength), as IPv6 clients commonly switch
	 * addresses within it. So is a login from any address of the network a
	 * login from this one. Entries remembered for a larger network, as
	 * earlier versions did, no longer count.
	 *
	 * Fail-closed: no, the address isn't trusted.
	 */
	public function hasLoggedInFrom($ipaddress, $username, $ipv6PrefixLength)
	{
		return $this->failClosed('hasLoggedInFrom', function () use ($ipaddress, $username, $ipv6PrefixLength)
		{
			$ipv6PrefixLength = IpHelper::trustPrefixLength($ipv6PrefixLength);
			$key = IpHelper::trackedAddress($ipaddress, $ipv6PrefixLength);
			$query = $this->db->createQuery()
				->select('COUNT(*)')
				->from($this->db->quoteName(self::Table))
				->whereIn($this->db->quoteName('ipaddress'), array($key, (string) $ipaddress), ParameterType::STRING)
				->where($this->usernameMatches('username'));
			$values = array('username' => (string) $username);
			if ($this->count($query, $values) > 0)
			{
				return true;
			}
			if (strpos($ipaddress, ':') === false)
			{
				return false;
			}
			// IPv6: look for entries under another spelling of the address,
			// or recorded at another granularity (the setting was changed)
			$query = $this->db->createQuery()
				->select($this->db->quoteName('ipaddress'))
				->from($this->db->quoteName(self::Table))
				->where($this->usernameMatches('username'));
			$values = array('username' => (string) $username);
			$knownAddresses = $this->column($query, $values);
			$ipBin = @inet_pton($ipaddress);
			foreach ($knownAddresses as $known)
			{
				if (strpos($known, '/') !== false)
				{
					$match = (int) substr($known, strpos($known, '/') + 1) >= IpHelper::TrustPrefixLength &&
						IpHelper::isInSubnet($ipaddress, $known);
				}
				else
				{
					$knownBin = @inet_pton($known);
					$match = $knownBin !== false &&
						($knownBin === $ipBin || IpHelper::trackedAddress($known, $ipv6PrefixLength) === $key);
				}
				if ($match)
				{
					return true;
				}
			}
			return false;
		}, false);
	}

	/**
	 * How many different accounts have logged in from $key (the key a
	 * client is trusted by, see IpHelper::trustPrefixLength()). Several
	 * accounts behind one address: a proxy, a NAT - or an office. Fail-open:
	 * 0.
	 */
	public function countAccountsFrom($key): int
	{
		return $this->failOpen('countAccountsFrom', function () use ($key)
		{
			$query = $this->db->createQuery()
				->select('COUNT(DISTINCT '.$this->db->quoteName('username_lc').')')
				->from($this->db->quoteName(self::Table))
				->where($this->db->quoteName('ipaddress').' = :ip');
			return $this->count($query, array('ip' => (string) $key));
		}, 0);
	}

	/**
	 * Forgets the addresses users logged in from longer ago than $maxAgeDays,
	 * and, oldest first, as many more as needed to keep at most $maxRows.
	 * Fail-open: the next run does it.
	 */
	public function prune($maxAgeDays = null, $maxRows = null)
	{
		$maxAgeDays = $maxAgeDays ?? self::MaxAgeDays;
		$maxRows = $maxRows ?? self::MaxRows;
		$this->failOpen('prune', function () use ($maxAgeDays, $maxRows)
		{
			$this->deleteBefore(self::Table, 'last_success', self::daysAgo($maxAgeDays));
			$this->trimOldest(self::Table, 'id', 'last_success ASC', $maxRows, 1000, ParameterType::INTEGER);
		}, null);
	}

	/**
	 * The addresses (keys) users have logged in from. Fail-open: none.
	 *
	 * @return string[]
	 */
	public function addresses()
	{
		return $this->failOpen('addresses', function ()
		{
			return $this->column($this->db->createQuery()
				->select('DISTINCT '.$this->db->quoteName('ipaddress'))
				->from($this->db->quoteName(self::Table)));
		}, array());
	}

	/**
	 * Forgets the logins from $addresses: a proxy's address, which became a
	 * "known address" of every user who logged in through it. Fail-open:
	 * they stay.
	 *
	 * @param string[] $addresses
	 */
	public function forgetAddresses(array $addresses)
	{
		$addresses = array_values(array_unique(array_map('strval', $addresses)));
		if (count($addresses) === 0)
		{
			return;
		}
		$this->failOpen('forgetAddresses', function () use ($addresses)
		{
			$this->execute($this->db->createQuery()
				->delete($this->db->quoteName(self::Table))
				->whereIn($this->db->quoteName('ipaddress'), $addresses, ParameterType::STRING));
		}, null);
	}
}
