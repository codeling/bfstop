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
}
