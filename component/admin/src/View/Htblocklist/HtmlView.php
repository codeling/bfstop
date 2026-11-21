<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Htblocklist;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Controller\HtblockController;
use Codeling\Component\Bfstop\Administrator\Controller\HtblocklistController;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;

class HtmlView extends BaseHtmlView
{
	/** @var object[] */
	protected $items = array();
	protected \Joomla\CMS\Pagination\Pagination $pagination;
	protected string $sortColumn = '';
	protected string $sortDirection = '';

	public function display($tpl = null)
	{
		$this->items      = $this->getModel()->getItems();
		$this->pagination = $this->getModel()->getPagination();
		$state            = $this->getModel()->getState();
		$this->sortColumn = (string) $state->get('list.ordering');
		$this->sortDirection = (string) $state->get('list.direction');
		// selecting a range of rows with shift-click, see grid.checkall in the head
		$this->getDocument()->getWebAssetManager()->useScript('multiselect');
		$this->addToolBar();
		parent::display($tpl);
	}

	protected function addToolBar()
	{
		$user = Factory::getApplication()->getIdentity();
		ToolbarHelper::title(Text::_('COM_BFSTOP_HEADING_HTACCESS_BLOCKLIST'), 'bfstop');
		ToolbarHelper::divider();
		// the same rule as the task, see HtblocklistController::mayRemove()
		if (HtblocklistController::mayRemove($user))
		{
			// batch unblock would require rewrite of unblock method to check
			// for selected lines
			ToolbarHelper::custom('htblocklist.unblock', 'unpublish', '', 'COM_BFSTOP_UNBLOCK', true);
		}
		// an entry is part of the web server's configuration, see
		// HtblockController::save()
		if (HtblockController::mayAdd($user))
		{
			ToolbarHelper::addNew('htblock.add');
		}
	}
}
