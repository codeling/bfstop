<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Allowlist;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ToolbarHelper as BfstopToolbarHelper;
use Joomla\CMS\Factory;
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

	protected function addToolBar()
	{
		$user = Factory::getApplication()->getIdentity();
		ToolbarHelper::title(Text::_('COM_BFSTOP_HEADING_ALLOWLIST'), 'bfstop');
		ToolbarHelper::divider();
		if ($user->authorise('core.delete', 'com_bfstop'))
		{
			ToolbarHelper::deleteList('COM_BFSTOP_ALLOWLIST_DELETE_CONFIRM', 'allowlist.remove');
		}
		if ($user->authorise('core.edit', 'com_bfstop'))
		{
			ToolbarHelper::editList('allow.edit');
		}
		if ($user->authorise('core.create', 'com_bfstop'))
		{
			ToolbarHelper::addNew('allow.add');
		}
		BfstopToolbarHelper::addOptions();
	}
}
