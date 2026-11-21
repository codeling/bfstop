<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Table;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\IpHelper;
use Joomla\CMS\Table\Table;
use Joomla\Database\DatabaseDriver;

class BlockTable extends Table
{
	public function __construct(DatabaseDriver $db)
	{
		parent::__construct('#__bfstop_bannedip', 'id', $db);
	}

	public function check()
	{
		// a new entry comes with an empty id from the edit form; MySQL turns
		// that into the next auto-increment value, but PostgreSQL rejects it
		// (as NULL for the id column) - 0 makes Joomla leave the id out of
		// the INSERT on both (issue bfstop#206)
		if (empty($this->id))
		{
			$this->id = 0;
		}
		// addresses and networks are looked up by their canonical spelling, see
		// IpHelper::canonicalEntry() ("2001:DB8::1" and "203.0.113.5/24" are
		// kept as "2001:db8::1" and "203.0.113.0/24")
		$canonical = IpHelper::canonicalEntry($this->ipaddress);
		if ($canonical !== null)
		{
			$this->ipaddress = $canonical;
		}
		// minutes, 0 for ever: the list names some, but a block may last any
		// number of them (see BlockModel::addDurationOption()) - just not fewer
		// than none
		if (!is_numeric($this->duration) || (int) $this->duration < 0 || (string) (int) $this->duration !== trim((string) $this->duration))
		{
			$this->setError(\Joomla\CMS\Language\Text::_('COM_BFSTOP_BLOCK_DURATION_INVALID'));
			return false;
		}
		$this->duration = (int) $this->duration;
		$this->crdate = self::startTime((string) $this->crdate, $this->storedStartTime(), date('Y-m-d H:i:s'));
		if (\DateTime::createFromFormat('!Y-m-d H:i:s', $this->crdate) === false)
		{
			$this->setError(\Joomla\CMS\Language\Text::_('COM_BFSTOP_BLOCK_START_INVALID'));
			return false;
		}
		return parent::check();
	}

	/**
	 * When the block is to start, from what the form gives for it. The form
	 * only takes the day, which used to be stored as its midnight: a block
	 * of an hour added in the afternoon had run out already, and editing a
	 * block moved its start back to the midnight before. So a day without
	 * a time means
	 *
	 * - the day the block already starts on (it is edited): the time it
	 *   starts at, unchanged;
	 * - today: now;
	 * - any other day: the beginning of that day.
	 *
	 * Nothing means now; a time given with the day is kept. Times are those
	 * of PHP's date(), like the plugin's.
	 *
	 * @param string      $given  the value of the form
	 * @param string|null $stored the start of the block as it is stored, null for a new block
	 * @param string      $now    date('Y-m-d H:i:s')
	 */
	public static function startTime($given, $stored, $now)
	{
		$given = trim((string) $given);
		if ($given === '')
		{
			return $now;
		}
		$day = \DateTime::createFromFormat('!Y-m-d', $given);
		if ($day === false || $day->format('Y-m-d') !== $given)
		{
			return $given;
		}
		if ($stored !== null && strncmp((string) $stored, $given, 10) === 0)
		{
			return (string) $stored;
		}
		if (strncmp($now, $given, 10) === 0)
		{
			return $now;
		}
		return $given.' 00:00:00';
	}

	/**
	 * The start of this block as it is stored, null for a new one.
	 */
	private function storedStartTime()
	{
		if (empty($this->id))
		{
			return null;
		}
		$db = $this->getDatabase();
		$query = $db->createQuery()
			->select($db->quoteName('crdate'))
			->from($db->quoteName($this->_tbl))
			->where($db->quoteName('id').' = '.(int) $this->id);
		$db->setQuery($query);
		$stored = $db->loadResult();
		return ($stored === null || $stored === false) ? null : (string) $stored;
	}
}
