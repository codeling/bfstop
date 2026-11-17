<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Htblock;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;

class HtmlView extends BaseHtmlView
{
	protected $canSave;

	public function display($tpl = null)
	{
		$this->form = $this->getModel()->getForm();
		$this->item = $this->getModel()->getItem();

		$user = Factory::getApplication()->getIdentity();
		$this->canSave = $user && $user->authorise('core.create', 'com_bfstop');

		$this->addToolbar();
		// the stylesheet is in the component's template folder, not in media/: a
		// path from the site's root, Joomla adds the prefix of a sub-folder install
		$this->getDocument()->getWebAssetManager()->registerAndUseStyle(
			'com_bfstop.htblock.edit', 'administrator/components/com_bfstop/tmpl/htblock/edit.css');
		parent::display($tpl);
	}

	protected function addToolbar()
	{
		$input = Factory::getApplication()->getInput();
		$input->set('hidemainmenu', true);
		ToolbarHelper::title(Text::_('COM_BFSTOP_BLOCK_NEW'));
		if ($this->canSave)
		{
			ToolbarHelper::save('htblock.save');
		}
		ToolbarHelper::cancel('htblock.cancel', 'JTOOLBAR_CANCEL');
	}
}
