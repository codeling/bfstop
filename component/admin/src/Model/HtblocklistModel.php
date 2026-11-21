<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\UnblockHelper;
use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Model\ListModel;

class HtblocklistModel extends ListModel
{
	protected $cachedHtAccessLines;

	public function __construct($config = array())
	{
		$config['filter_fields'] = array(
			'ipaddress'
		);
		$this->cachedHtAccessLines = null;
		parent::__construct($config);
	}

	private function getHtAccessLines()
	{
		if (is_null($this->cachedHtAccessLines))
		{
			$this->cachedHtAccessLines = array();
			$htaccessPath = UnblockHelper::getHtaccessPath();
			$htaccess = new HtaccessHelper($htaccessPath, null);
			$deniedIPs = $htaccess->getDeniedIPs();
			foreach ($deniedIPs as $ip)
			{
				$this->cachedHtAccessLines[] = $ip;
			}
		}
		return $this->cachedHtAccessLines;
	}

	/**
	 * The entries of the page starting at $start, $count of them - all from
	 * $start on if $count is 0, which is what the list's "All" sets.
	 */
	private function getPaginatedHtAccessLines($start, $count)
	{
		$items = $this->getHtAccessLines();
		if (strtolower((string) $this->getState('list.direction')) === 'asc')
		{
			sort($items);
		}
		else
		{
			rsort($items);
		}
		return array_slice($items, max(0, (int) $start), (int) $count > 0 ? (int) $count : null);
	}

	public function getItems()
	{
		return $this->getPaginatedHtAccessLines($this->getStart(), $this->getState('list.limit'));
	}

	protected function populateState($ordering = null, $direction = null)
	{
		parent::populateState('ipaddress', 'ASC');
	}

	public function unblock($ids, $logger)
	{
		if (UnblockHelper::unblockHtaccess($ids, $logger))
		{
			return Text::_("COM_BFSTOP_UNBLOCK_SUCCESS");
		}
		else
		{
			return Text::_("COM_BFSTOP_UNBLOCK_FAILED");
		}
	}

	public function getTotal()
	{
		return count($this->getHtAccessLines());
	}
}
