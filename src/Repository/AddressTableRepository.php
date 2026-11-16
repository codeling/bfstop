<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Repository;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use Joomla\Database\ParameterType;

/**
 * A table with a column "ipaddress" which holds addresses and networks in
 * canonical form (IpHelper::canonicalEntry()): the block and the allow list.
 * Which entries can match an address is known beforehand
 * (IpHelper::lookupCandidates()), so a lookup is a query by index. It used
 * to read every network of the table and test each in PHP, on every request
 * of every visitor - slow once a few thousand IPv6 clients were blocked, and a
 * way for them to slow the site down (the SQL was MySQL-only at first, see
 * issue #206, and the source of #117, #134 and #142).
 */
abstract class AddressTableRepository extends Repository
{
	/** the table: a constant of the subclass, never a value from outside */
	protected const Table = '';
	/** what the debug log says about an entry which matched */
	protected const MatchLabel = 'Matched';

	/**
	 * The ids and addresses of the rows of the table which contain
	 * $ipaddress, the address itself or a network it is part of, and which
	 * satisfy $refine (a callable which adds conditions to the query, with
	 * the table aliased "t", and returns the values (name => value) of the
	 * parameters it used). Whatever fails, the exception goes to the caller:
	 * which policy applies is the public method's to decide.
	 *
	 * @return object[]
	 */
	protected function loadMatching($ipaddress, ?callable $refine = null)
	{
		$candidates = IpHelper::lookupCandidates($ipaddress);
		if (count($candidates) === 0)
		{
			return array();
		}
		$query = $this->db->createQuery()
			->select($this->db->quoteName(array('t.id', 't.ipaddress')))
			->from($this->db->quoteName(static::Table, 't'))
			->whereIn($this->db->quoteName('t.ipaddress'), $candidates, ParameterType::STRING);
		$entries = $this->objects($query, $refine !== null ? $refine($query) : array());
		foreach ($entries as $entry)
		{
			$this->logger->log(static::MatchLabel." because of entry: ".
				"id=".$entry->id.", ".
				"ipaddress=".$entry->ipaddress,
				\Joomla\CMS\Log\Log::DEBUG);
		}
		return $entries;
	}

	/**
	 * Brings the addresses of the table into canonical form
	 * (IpHelper::canonicalEntry()), which lookups depend on: entries written
	 * by earlier versions, or by hand, may be spelled differently
	 * ("2001:DB8::1", "203.0.113.5/24"). Entries which are no address or
	 * network are left alone.
	 *
	 * Fail-open: what isn't done now is done by the next run.
	 *
	 * @return int the number of entries changed
	 */
	public function canonicalize()
	{
		return $this->failOpen('canonicalize', function ()
		{
			$changed = 0;
			$lastId = 0;
			do
			{
				$query = $this->db->createQuery()
					->select($this->db->quoteName(array('id', 'ipaddress')))
					->from($this->db->quoteName(static::Table))
					->where($this->db->quoteName('id').' > :last')
					->order($this->db->quoteName('id').' ASC');
				$values = array('last' => $lastId);
				$rows = $this->objects($query, $values, 0, 5000);
				foreach ($rows as $row)
				{
					$lastId = (int) $row->id;
					$canonical = IpHelper::canonicalEntry($row->ipaddress);
					if ($canonical !== null && $canonical !== $row->ipaddress)
					{
						$update = $this->db->createQuery()
							->update($this->db->quoteName(static::Table))
							->set($this->db->quoteName('ipaddress').' = :canonical')
							->where($this->db->quoteName('id').' = :id');
						$updateValues = array('canonical' => $canonical, 'id' => (int) $row->id);
						$this->execute($update, $updateValues);
						++$changed;
					}
				}
			}
			while (count($rows) === 5000);
			return $changed;
		}, 0);
	}
}
