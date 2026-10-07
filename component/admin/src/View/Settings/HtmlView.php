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
use Joomla\CMS\Access\Exception\NotAllowed;
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
		// the settings show where the plugin writes files, which proxy it
		// trusts and who gets the notifications: not for everybody who may
		// merely look at the lists
		if (!Factory::getApplication()->getIdentity()->authorise('core.admin', 'com_bfstop'))
		{
			throw new NotAllowed(Text::_('JERROR_ALERTNOAUTHOR'), 403);
		}
		// the form field labels/descriptions are reused verbatim from the
		// plugin's own language file; that file isn't auto-loaded for us.
		// the strings live in the .sys.ini, not the plain .ini - see
		// InstallerAdapter::doLoadLanguage() for the same load pattern.
		$language = Factory::getLanguage();
		$language->load('plg_system_bfstop.sys', JPATH_ADMINISTRATOR)
			|| $language->load('plg_system_bfstop.sys', JPATH_PLUGINS . '/system/bfstop');

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
			'COM_BFSTOP_TEST_NOTIFICATION', false, false);
		BfstopToolbarHelper::addOptions();
	}
}
