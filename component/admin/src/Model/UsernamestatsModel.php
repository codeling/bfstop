<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

use Joomla\CMS\MVC\Model\ListModel;

/**
 * Per-username failed login statistics (issue #136), maintained by the
 * plugin in #__bfstop_username_stats; unlike the failed login entries,
 * these are not removed by the automatic purge.
 */
class UsernamestatsModel extends ListModel
{
	public function __construct($config = array())
	{
		$config['filter_fields'] = array(
			's.username',
			's.attempts',
			's.first_attempt',
			's.last_attempt'
		);
		parent::__construct($config);
	}

	protected function getListQuery()
	{
		$db = $this->getDatabase();
		$query = $db->getQuery(true);
		$query->select('s.username, s.attempts, s.first_attempt, s.last_attempt, u.id AS user_id');
		$query->from('#__bfstop_username_stats s');
		$query->join('LEFT', '#__users u ON u.username = s.username');
		$ordering  = $this->getState('list.ordering', 's.attempts');
		$ordering  = (strcmp($ordering, '') == 0) ? 's.attempts' : $ordering;
		$direction = $this->getState('list.direction', 'DESC');
		$direction = (strcmp($direction, '') == 0) ? 'DESC' : $direction;
		$query->order($db->escape($ordering).' '.$db->escape($direction));
		return $query;
	}

	protected function populateState($ordering = null, $direction = null)
	{
		parent::populateState('s.attempts', 'DESC');
	}

	/**
	 * @return int the highest number of attempts for a single username,
	 *             used as reference for the bars in the list
	 */
	public function getMaxAttempts()
	{
		$db = $this->getDatabase();
		$query = $db->getQuery(true);
		$query->select('MAX(attempts)')
			->from($db->quoteName('#__bfstop_username_stats'));
		$db->setQuery($query);
		return (int) $db->loadResult();
	}

	/**
	 * Delete the statistics of all usernames which were not used in a failed
	 * login during the given number of days.
	 *
	 * @return int the number of deleted usernames
	 */
	public function purgeNotSeenFor(int $days)
	{
		// last_attempt is written with PHP's date() by the plugin, so compute
		// the cutoff with the same clock instead of the database's NOW()
		$cutoff = date('Y-m-d H:i:s', time() - $days * 86400);
		$db = $this->getDatabase();
		$query = $db->getQuery(true);
		$query->delete($db->quoteName('#__bfstop_username_stats'))
			->where($db->quoteName('last_attempt').' < :cutoff')
			->bind(':cutoff', $cutoff);
		$db->setQuery($query);
		$db->execute();
		return $db->getAffectedRows();
	}
}
