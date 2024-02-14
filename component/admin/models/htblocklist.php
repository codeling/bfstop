<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Model\ListModel;

require_once(JPATH_ADMINISTRATOR.'/components/com_bfstop/helpers/unblock.php');
require_once(JPATH_SITE.'/plugins/system/bfstop/helpers/htaccess.php');

class BFStopModelHTBlockList extends ListModel
{
	protected $cachedHtAccessLines;

	public function __construct($config = array())
	{
		$config['filter_fields'] = array(
			'ipaddress'
		);
		$cachedHtAccessLines = null;
		parent::__construct($config);
	}

	private function getHtAccessLines()
	{
		if (is_null($this->cachedHtAccessLines))
		{
			$this->cachedHtAccessLines = array();
			$htaccessPath = BFStopParamHelper::get('htaccessPath', 'params', JPATH_ROOT);
			$htaccessPath = $htaccessPath === "" ? JPATH_ROOT : $htaccessPath;
			$htaccess = new BFStopHtAccess($htaccessPath, null);
			$deniedIPs = $htaccess->getDeniedIPs();
			foreach($deniedIPs as $ip)
			{
				$this->cachedHtAccessLines[] = $ip;
			}
		}
		return $this->cachedHtAccessLines;
	}

	private function getPaginatedHtAccessLines($start, $count)
	{
		$direction = $this->getState('list.direction');
		$items = $this->getHtAccessLines();
		if (strtolower($direction) === 'asc')
		{
			sort($items);
		}
		else
		{
			rsort($items);
		}
		$current = 0;
		$result = array();
		foreach($items as $entry)
		{
			if ($current >= $start)
			{
				if (($current - $start) >= $count)
				{
					break;
				}
				$result[] = $entry;
			}
			$current++;
		}
		return $result;
	}

	public function getItems()
	{
		$start = $this->getStart();
		$count = $this->getState('list.limit');
		$result = $this->getPaginatedHtAccessLines($start, $count);
		return $result;
	}

	protected function populateState($ordering = null, $direction = null) {
		parent::populateState('ipaddress', 'ASC');
	}

	public function unblock($ids, $logger)
	{
		if (BFStopUnblockHelper::unblockHtaccess($ids, $logger)) {
			return Text::_("UNBLOCK_SUCCESS");
		} else {
			return Text::_("UNBLOCK_FAILED");
		}
	}

	public function getTotal()
	{
		return count($this->getHtAccessLines());
	}
}
