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
use Joomla\CMS\MVC\View\HtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;

require_once(JPATH_ADMINISTRATOR.'/components/com_bfstop/helpers/links.php');

class BFStopViewFailedLoginList extends HtmlView
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
	function getOriginName($origin)
	{
		return ($origin == 0) ? 'Frontend': 'Backend';
	}
	protected function addToolBar()
	{
		ToolbarHelper::title(Text::_('COM_BFSTOP_HEADING_FAILEDLOGINLIST'), 'bfstop');
		BFStopToolbarHelper::addOptions();
	}
}
