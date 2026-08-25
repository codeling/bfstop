<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Htblocklist;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ToolbarHelper as BfstopToolbarHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;

class HtmlView extends BaseHtmlView
{
	function display($tpl = null)
	{
		$this->items      = $this->get('Items');
		$this->pagination = $this->get('Pagination');
		$state            = $this->get('State');
		$this->sortColumn = $state->get('list.ordering');
		$this->sortDirection = $state->get('list.direction');
		$this->addToolBar();
		parent::display($tpl);
	}

	function getBlockedState($item)
	{
		if ($item->unblocked != null)
		{
			return Text::sprintf('UNBLOCKED_STATE', $item->unblocked);
		}
		else
		{
			if ($item->duration == 0)
			{
				return Text::_('BLOCKED_PERMANENTLY');
			}
			else
			{
				$blockedUntil = strtotime($item->crdate);
				$blockedUntil += $item->duration * 60;
				$strDate = date('Y-m-d H:i:s', $blockedUntil);
				return ($blockedUntil < time())
					? Text::sprintf('BLOCK_EXPIRED_AT', $strDate)
					: Text::sprintf('BLOCKED_UNTIL', $strDate);
			}
		}
	}

	function convertDurationToReadable($duration)
	{
		if ($duration == 0)
		{
			return Text::_('COM_BFSTOP_BLOCK_UNLIMITED');
		}
		elseif ($duration >= 1 && $duration <= 59)
		{
			return Text::_('COM_BFSTOP_BLOCK_'.$duration.'MINUTES');
		}
		elseif ($duration == 60)
		{
			return Text::_('COM_BFSTOP_BLOCK_1HOUR');
		}
		else
		{
			return Text::_('COM_BFSTOP_BLOCK_'.($duration / 60).'HOURS');
		}
	}

	protected function addToolBar()
	{
		ToolbarHelper::title(Text::_('COM_BFSTOP_HEADING_HTACCESS_BLOCKLIST'), 'bfstop');
		ToolbarHelper::divider();
		// batch unblock would require rewrite of unblock method to check
		// for selected lines
		ToolbarHelper::custom('htblocklist.unblock', 'unpublish.png', 'unpublish_f2.png', 'COM_BFSTOP_UNBLOCK', true);
		ToolbarHelper::addNew('htblock.add');
		BfstopToolbarHelper::addOptions();
	}
}
