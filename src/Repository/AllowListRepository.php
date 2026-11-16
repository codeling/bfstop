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

/**
 * The addresses and networks which are never blocked (#__bfstop_allowlist).
 */
class AllowListRepository extends AddressTableRepository
{
	protected const Table = '#__bfstop_allowlist';
	protected const MatchLabel = 'Allowed';

	/**
	 * Whether $ipaddress, or a network it is part of, is on the list.
	 *
	 * Fail-closed: an allow list which can't be read allows nothing.
	 */
	public function contains($ipaddress)
	{
		return $this->failClosed('contains', function () use ($ipaddress)
		{
			return count($this->loadMatching($ipaddress)) > 0;
		}, false);
	}

	/**
	 * The entries of the allow list which overlap the address or network
	 * $entry (see IpHelper::overlapping()): what a block of $entry in the
	 * .htaccess file would turn away as well - the web server knows nothing
	 * of the allow list. contains() only answers for an address. The allow
	 * list is kept by the administrators (core.admin), so it is short.
	 *
	 * Unknown (null) if the list can't be read: the caller assumes every
	 * entry overlaps.
	 *
	 * @return string[]|null
	 */
	public function entriesOverlapping($entry)
	{
		return $this->unknown('entriesOverlapping', function () use ($entry)
		{
			$this->db->setQuery($this->db->createQuery()
				->select($this->db->quoteName('ipaddress'))
				->from($this->db->quoteName(self::Table)));
			return IpHelper::overlapping($entry, $this->db->loadColumn());
		});
	}
}
