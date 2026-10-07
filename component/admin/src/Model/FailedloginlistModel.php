<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Model\ListModel;

class FailedloginlistModel extends ListModel
{
	public function __construct($config = array())
	{
		$config['filter_fields'] = array(
			'l.id',
			'l.username',
			'l.ipaddress',
			'l.logtime',
			'l.origin'
		);
		parent::__construct($config);
	}

	protected function getListQuery()
	{
		$db = Factory::getDbo();
		$query = $db->getQuery(true);
		$query->select('l.id, l.username, l.ipaddress, l.logtime, l.origin');
		$query->from('#__bfstop_failedlogin l');
		$username = (string) $this->getState('filter.username', '');
		if ($username !== '')
		{
			$query->where('l.username = :username')
				->bind(':username', $username);
		}
		$ordering  = $this->getState('list.ordering', 'l.id');
		$ordering  = (strcmp($ordering, '') == 0) ? 'l.id' : $ordering;
		$direction = $this->getState('list.direction', 'ASC');
		$direction = (strcmp($direction, '') == 0) ? 'ASC' : $direction;
		$query->order($db->escape($ordering).' '.$db->escape($direction));
		return $query;
	}

	protected function populateState($ordering = null, $direction = null)
	{
		parent::populateState('l.logtime', 'DESC');
		// set when coming from the username statistics view; deliberately not
		// persisted in the user state, so the full list shows otherwise
		$this->setState('filter.username',
			Factory::getApplication()->input->getString('filter_username', ''));
	}

	/**
	 * Delete all failed login entries older than the given number of days.
	 * Only touches the failed login table; blocks, unblock tokens etc. are
	 * left alone (those are handled by the plugin's automatic purge).
	 *
	 * @return int the number of deleted entries
	 */
	public function purgeOlderThan(int $days)
	{
		// logtime is written with PHP's date() by the plugin, so compute the
		// cutoff with the same clock instead of the database's NOW()
		$cutoff = date('Y-m-d H:i:s', time() - $days * 86400);
		$db = Factory::getDbo();
		$query = $db->getQuery(true);
		$query->delete($db->quoteName('#__bfstop_failedlogin'))
			->where($db->quoteName('logtime').' < :cutoff')
			->bind(':cutoff', $cutoff);
		$db->setQuery($query);
		$db->execute();
		return $db->getAffectedRows();
	}
}
