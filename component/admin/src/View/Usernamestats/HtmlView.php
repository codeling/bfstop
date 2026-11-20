<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Usernamestats;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Repository\UsernameStatsRepository;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Toolbar\ToolbarHelper;

class HtmlView extends BaseHtmlView
{
	/** @var object[] */
	protected $items = array();
	protected \Joomla\CMS\Pagination\Pagination $pagination;
	protected string $sortColumn = '';
	protected string $sortDirection = '';
	protected int $maxAttempts = 0;
	protected int $maxUsernames = 0;
	protected bool $canPurge = false;

	public function display($tpl = null)
	{
		$this->items      = $this->getModel()->getItems();
		$this->pagination = $this->getModel()->getPagination();
		$state            = $this->getModel()->getState();
		$this->sortColumn = (string) $state->get('list.ordering');
		$this->sortDirection = (string) $state->get('list.direction');
		$this->maxAttempts = (int) $this->getModel()->getMaxAttempts();
		$this->maxUsernames = (int) UsernameStatsRepository::MaxRows;
		$this->canPurge   = (bool) Factory::getApplication()->getIdentity()->authorise('core.delete', 'com_bfstop');
		if ($this->canPurge)
		{
			Factory::getApplication()->getDocument()->getWebAssetManager()->useScript('bootstrap.modal');
		}
		$this->addToolBar();
		parent::display($tpl);
	}

	public function getFailedLoginsLink($username)
	{
		return Route::_('index.php?option=com_bfstop&view=failedloginlist&filter_username='.
			rawurlencode($username), false);
	}

	public function getBarWidth($attempts)
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
	}
}
