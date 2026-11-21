<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ActionLogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\OrderingHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Model\ListModel;

class AllowlistModel extends ListModel
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
		$db = $this->getDatabase();
		$query = $db->createQuery();
		$query->select('a.id, a.ipaddress, a.notes');
		$query->from('#__bfstop_allowlist a');
		$query->order(OrderingHelper::clause($db, $this->getState('list.ordering'), $this->getState('list.direction'),
			$this->filter_fields, 'a.id', 'ASC'));
		return $query;
	}

	protected function populateState($ordering = null, $direction = null)
	{
		parent::populateState('a.id', 'ASC');
	}

	public function remove($ids, $logger)
	{
		$ids = array_values(array_filter(array_map('intval', (array) $ids)));
		if (count($ids) === 0)
		{
			return Text::_('COM_BFSTOP_ALLOWLIST_NOTHING_REMOVED');
		}
		$addresses = ActionLogHelper::addresses('#__bfstop_allowlist', $ids);
		try
		{
			$db = $this->getDatabase();
			$query = $db->createQuery();
			$conditions = array(
				$db->quoteName('id').' IN ('.implode(", ", $ids).')'
			);
			$query->delete($db->quoteName('#__bfstop_allowlist'));
			$query->where($conditions);
			$db->setQuery($query);
			$db->execute();
			ActionLogHelper::log('allow_removed', array('ipaddresses' => array_values($addresses)));
			return Text::_('COM_BFSTOP_ALLOWLIST_REMOVED');
		}
		catch (\RuntimeException $e)
		{
			$logger->log($e->getMessage(), Log::ERROR);
			return Text::_('COM_BFSTOP_ALLOWLIST_REMOVE_FAILED');
		}
	}
}
