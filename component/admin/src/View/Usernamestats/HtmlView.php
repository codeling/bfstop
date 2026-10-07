<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Usernamestats;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ToolbarHelper as BfstopToolbarHelper;
use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Router\Route;
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
		$this->maxAttempts = $this->get('MaxAttempts');
		$this->maxUsernames = DatabaseHelper::$USERNAME_STATS_MAX_ROWS;
		$this->canPurge   = Factory::getApplication()->getIdentity()->authorise('core.delete', 'com_bfstop');
		if ($this->canPurge)
		{
			Factory::getApplication()->getDocument()->getWebAssetManager()->useScript('bootstrap.modal');
		}
		$this->addToolBar();
		parent::display($tpl);
	}

	function getFailedLoginsLink($username)
	{
		return Route::_('index.php?option=com_bfstop&view=failedloginlist&filter_username='.
			rawurlencode($username), false);
	}

	function getBarWidth($attempts)
	{
		return ($this->maxAttempts > 0)
			? max(1, (int) round(100 * $attempts / $this->maxAttempts))
			: 0;
	}

	protected function addToolBar()
	{
		ToolbarHelper::title(Text::_('COM_BFSTOP_HEADING_USERNAMESTATS'), 'bfstop');
		if ($this->canPurge)
		{
			ToolbarHelper::modal('bfstopPurgeModal', 'icon-trash', 'COM_BFSTOP_USERNAMESTATS_PURGE_BUTTON');
		}
		BfstopToolbarHelper::addOptions();
	}
}
