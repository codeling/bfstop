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
use Joomla\CMS\Uri\Uri;

class BFStopViewHTBlock extends HtmlView
{
	public function display($tpl = null)
	{
		$this->form = $this->get('Form');
		$this->item = $this->get('Item');
		$this->addToolbar();
		$document = Factory::getDocument();
		$document->addStyleSheet(Uri::base(true).
			'/components/com_bfstop/views/htblock/tmpl/edit.css');
		parent::display($tpl);
	}
	protected function addToolbar()
	{
		$input = Factory::getApplication()->input;
		$input->set('hidemainmenu', true);
		ToolbarHelper::title(Text::_('COM_BFSTOP_BLOCK_NEW'));
		ToolbarHelper::save('htblock.save');
		ToolbarHelper::cancel('htblock.cancel', 'JTOOLBAR_CANCEL');
	}
}
