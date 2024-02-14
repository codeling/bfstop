<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Model\ListModel;

class BFStopModelAllowList extends ListModel
{
	public function __construct($config = array())
	{
		$config['filter_fields'] = array(
			'a.id',
			'a.ipaddress',
			'a.notes'
		);
		parent::__construct($config);
	}

	protected function getListQuery()
	{
		$db = Factory::getDBO();
		$query = $db->getQuery(true);
		$query->select('a.id, a.ipaddress, a.notes');
		$query->from('#__bfstop_allowlist a');
		$ordering  = $this->getState('list.ordering', 'a.id');
		$ordering  = (strcmp($ordering, '') == 0) ? 'a.id' : $ordering;
		$direction = $this->getState('list.direction', 'ASC');
		$direction = (strcmp($direction, '') == 0) ? 'ASC' : $direction;
		$query->order($db->escape($ordering).' '.$db->escape($direction));
		return $query;
	}

	protected function populateState($ordering = null, $direction = null) {
		parent::populateState('a.id', 'ASC');
	}

	public function remove($ids, $logger)
	{
		try {
			$db = Factory::getDBO();
			$query = $db->getQuery(true);
			$conditions = array(
				$db->quoteName('id').' IN ('.implode(", ", $ids).')'
			);
			$query->delete($db->quoteName('#__bfstop_allowlist'));
			$query->where($conditions);
			$db->setQuery($query);
			$db->execute();
		} catch (RuntimeException $e) {
			$logger->log($e->getMessage(), Log::ERROR);
		}
	}

}
