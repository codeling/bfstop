<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Failedloginlist;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ParamHelper;
use Codeling\Component\Bfstop\Administrator\Helper\ToolbarHelper as BfstopToolbarHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;

class HtmlView extends BaseHtmlView
{
	function display($tpl = null)
	{
		$this->items      = $this->getModel()->getItems();
		$this->pagination = $this->getModel()->getPagination();
		$state            = $this->getModel()->getState();
		$this->sortColumn = $state->get('list.ordering');
		$this->sortDirection = $state->get('list.direction');
		$this->filterUsername = (string) $state->get('filter.username', '');
		$this->autoPurgeWeeks = (int) ParamHelper::get('deleteOld', 'params', 0);
		$this->canPurge   = Factory::getApplication()->getIdentity()->authorise('core.delete', 'com_bfstop');
		if ($this->canPurge)
		{
			Factory::getApplication()->getDocument()->getWebAssetManager()->useScript('bootstrap.modal');
		}
		$this->addToolBar();
		parent::display($tpl);
	}

	function getOriginName($origin)
	{
		return ($origin == 0) ? 'Frontend' : 'Backend';
	}

	protected function addToolBar()
	{
		ToolbarHelper::title(Text::_('COM_BFSTOP_HEADING_FAILEDLOGINLIST'), 'bfstop');
		if ($this->canPurge)
		{
			ToolbarHelper::modal('bfstopPurgeModal', 'icon-trash', 'COM_BFSTOP_FAILEDLOGIN_PURGE_BUTTON');
		}
		BfstopToolbarHelper::addOptions();
	}
}
