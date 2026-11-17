<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Repository;

defined('_JEXEC') or die;

/**
 * The plugin's own bookkeeping (#__bfstop_state: name => value), apart from
 * its settings. It lived in the settings - the plugin's row of #__extensions -
 * where whoever wrote a value wrote all the settings back as they had read
 * them, and so raced with an administrator saving the settings page.
 */
class StateRepository extends Repository
{
	private const Table = '#__bfstop_state';

	/** the time (a Unix timestamp) the daily maintenance last ran */
	public const LastMaintenance = 'lastMaintenance';

	/**
	 * What is stored under $name. Fail-open: $default (what is not known is
	 * taken for never having happened - the maintenance is run again).
	 */
	public function get($name, $default = null)
	{
		return $this->failOpen('get', function () use ($name, $default)
		{
			$query = $this->db->createQuery()
				->select($this->db->quoteName('value'))
				->from($this->db->quoteName(self::Table))
				->where($this->db->quoteName('name').' = :name');
			$value = $this->scalar($query, array('name' => (string) $name));
			return $value === null ? $default : $value;
		}, $default);
	}

	/**
	 * Stores $value under $name. Fail-open: not stored (the maintenance is
	 * run again).
	 */
	public function set($name, $value)
	{
		$this->failOpen('set', function () use ($name, $value)
		{
			$now = self::now();
			$update = $this->db->createQuery()
				->update($this->db->quoteName(self::Table))
				->set($this->db->quoteName('value').' = :value')
				->set($this->db->quoteName('changed').' = :changed')
				->where($this->db->quoteName('name').' = :name');
			$values = array('value' => (string) $value, 'changed' => $now, 'name' => (string) $name);
			$this->execute($update, $values);
			if ($this->db->getAffectedRows() > 0)
			{
				return;
			}
			// no row yet (or none changed: the same value at the same second): insert,
			// unless another request just did
			$exists = $this->scalar($this->db->createQuery()
				->select($this->db->quoteName('name'))
				->from($this->db->quoteName(self::Table))
				->where($this->db->quoteName('name').' = :name'), array('name' => (string) $name));
			if ($exists !== null)
			{
				return;
			}
			$this->insert(self::Table, array('name' => (string) $name, 'value' => (string) $value, 'changed' => $now));
		}, null);
	}
}
