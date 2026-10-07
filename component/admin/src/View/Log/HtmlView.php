<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Log;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ToolbarHelper as BfstopToolbarHelper;
use Codeling\Component\Bfstop\Administrator\Helper\ParamHelper;
use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use Joomla\CMS\Access\Exception\NotAllowed;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;

class HtmlView extends BaseHtmlView
{
	function display($tpl = null)
	{
		// the log holds addresses and usernames of failed logins and details
		// of how the plugin is set up
		if (!Factory::getApplication()->getIdentity()->authorise('core.admin', 'com_bfstop'))
		{
			throw new NotAllowed(Text::_('JERROR_ALERTNOAUTHOR'), 403);
		}
		$this->items      = $this->get('Items');
		$this->pagination = $this->get('Pagination');
		$state            = $this->get('State');
		$this->sortColumn = $state->get('list.ordering');
		$this->sortDirection = $state->get('list.direction');
		$this->keepDays = (int) ParamHelper::get('logKeepDays', 'params', LoggerHelper::DefaultKeepDays);
		$this->maxSizeMB = max(1, (int) ParamHelper::get('logMaxSize', 'params', LoggerHelper::DefaultMaxSizeMB));
		$this->canDelete = Factory::getApplication()->getIdentity()->authorise('core.delete', 'com_bfstop');
		if ($this->canDelete)
		{
			Factory::getApplication()->getDocument()->getWebAssetManager()->useScript('bootstrap.modal');
		}
		$this->addToolBar();
		parent::display($tpl);
	}

	protected function addToolBar()
	{
		ToolbarHelper::title(Text::_('COM_BFSTOP_HEADING_LOGS'), 'bfstop');
		if ($this->canDelete)
		{
			ToolbarHelper::custom('log.prune', 'refresh', '', 'COM_BFSTOP_LOG_PRUNE_BUTTON', false);
			ToolbarHelper::modal('bfstopClearLogModal', 'icon-trash', 'COM_BFSTOP_LOG_CLEAR_BUTTON');
		}
		ToolbarHelper::divider();
		BfstopToolbarHelper::addOptions();
	}
}
