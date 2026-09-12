<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Block;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;
use Joomla\CMS\Uri\Uri;

class HtmlView extends BaseHtmlView
{
	public function display($tpl = null)
	{
		$this->form = $this->get('Form');
		$this->item = $this->get('Item');
		$this->addToolbar();
		$document = Factory::getDocument();
		$document->addStyleSheet(Uri::base(true).
			'/components/com_bfstop/tmpl/block/edit.css');
		parent::display($tpl);
	}

	protected function addToolbar()
	{
		$input = Factory::getApplication()->input;
		$input->set('hidemainmenu', true);
		$isNew = ($this->item->id == 0);
		ToolbarHelper::title($isNew
			? Text::_('COM_BFSTOP_BLOCK_NEW')
			: Text::_('COM_BFSTOP_BLOCK_EDIT'));
		ToolbarHelper::save('block.save');
		ToolbarHelper::cancel('block.cancel', $isNew
			? 'JTOOLBAR_CANCEL' : 'JTOOLBAR_CLOSE');
	}
}
