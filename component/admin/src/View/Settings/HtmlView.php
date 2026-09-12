<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Settings;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ToolbarHelper as BfstopToolbarHelper;
use Codeling\Component\Bfstop\Administrator\Helper\VersionHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;

class HtmlView extends BaseHtmlView
{
	protected $form;
	protected $item;
	protected $canSave;
	protected $pluginVersion;
	protected $componentVersion;

	public function display($tpl = null)
	{
		// the form field labels/descriptions are reused verbatim from the
		// plugin's own language file; that file isn't auto-loaded for us.
		Factory::getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);

		$this->form = $this->get('Form');
		$this->item = $this->get('Item');

		$user = Factory::getApplication()->getIdentity();
		$this->canSave = $user && $user->authorise('core.admin', 'com_bfstop');

		$versions = VersionHelper::getInstalledVersions();
		$this->pluginVersion = $versions['plugin'];
		$this->componentVersion = $versions['component'];

		$this->addToolbar();
		parent::display($tpl);
	}

	protected function addToolbar()
	{
		ToolbarHelper::title(Text::_('COM_BFSTOP_HEADING_SETTINGS'));
		if ($this->canSave)
		{
			ToolbarHelper::apply('settings.apply');
			ToolbarHelper::save('settings.save');
		}
		ToolbarHelper::cancel('settings.cancel');
		ToolbarHelper::custom('settings.testNotify', 'preview', '',
			'TEST_NOTIFICATION', false, false);
		BfstopToolbarHelper::addOptions();
	}
}
