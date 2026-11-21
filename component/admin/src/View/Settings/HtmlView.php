<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Settings;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\VersionHelper;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Service\BlockPolicy;
use Joomla\CMS\Access\Exception\NotAllowed;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;
use Joomla\CMS\Uri\Uri;

class HtmlView extends BaseHtmlView
{
	protected \Joomla\CMS\Form\Form|false $form;
	protected $item;
	protected bool $canSave = false;
	protected string $pluginVersion = '';
	protected string $componentVersion = '';
	protected string $addressCheck = '';

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
		$language = Factory::getApplication()->getLanguage();
		$language->load('plg_system_bfstop.sys', JPATH_ADMINISTRATOR)
			|| $language->load('plg_system_bfstop.sys', JPATH_PLUGINS . '/system/bfstop');

		$this->form = $this->getModel()->getForm();
		$this->item = $this->getModel()->getItem();

		$user = Factory::getApplication()->getIdentity();
		$this->canSave = (bool) ($user && $user->authorise('core.admin', 'com_bfstop'));

		$versions = VersionHelper::getInstalledVersions();
		$this->pluginVersion = (string) $versions['plugin'];
		$this->componentVersion = (string) $versions['component'];

		$this->addressCheck = self::addressCheck($_SERVER, IpHelper::getAddress(LogHelper::getLogger()));

		if (!BlockPolicy::hasLiveSite())
		{
			Factory::getApplication()->enqueueMessage(self::liveSiteNote(), 'warning');
		}

		$this->addToolbar();
		parent::display($tpl);
	}

	/**
	 * What the settings page says if the site's $live_site isn't set (see
	 * BlockPolicy::effectiveNotifyBlockedUser()), with the line to put into
	 * configuration.php. The address it proposes is the one of this request,
	 * sent by the administrator's browser: shown for them to check, never
	 * used for anything.
	 */
	public static function liveSiteNote()
	{
		$line = 'public $live_site = '.var_export(rtrim(Uri::root(), '/'), true).';';
		return Text::sprintf('COM_BFSTOP_WARNING_NO_LIVE_SITE',
			'<code>'.htmlspecialchars($line, ENT_QUOTES, 'UTF-8').'</code>');
	}

	// how much of a forwarding header the check shows at most
	private const HeaderDisplayLength = 200;

	/**
	 * The check of the proxy settings on their tab: where the request of the
	 * administrator's browser came from, the forwarding headers it carried
	 * and which client address the plugin makes of that with the saved
	 * settings. An address which is not the one of the administrator's
	 * computer (the proxy's, one the browser can't have) shows that the
	 * settings don't fit, before visitors get blocked for it.
	 *
	 * @param array  $server $_SERVER
	 * @param string $used   IpHelper::getAddress() for the request
	 * @return string HTML
	 */
	public static function addressCheck(array $server, $used)
	{
		$escape = fn ($value) => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
		$lines = array(Text::sprintf('COM_BFSTOP_SETTINGS_ADDRESS_CHECK_REMOTE',
			'<code>'.$escape($server['REMOTE_ADDR'] ?? '').'</code>'));
		$headers = 0;
		foreach (IpHelper::KnownProxyHeaders as $header)
		{
			if (!isset($server[$header]) || (string) $server[$header] === '')
			{
				continue;
			}
			// HTTP_X_FORWARDED_FOR: X-Forwarded-For
			$name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($header, 5)))));
			$value = (string) $server[$header];
			if (mb_strlen($value, 'UTF-8') > self::HeaderDisplayLength)
			{
				$value = mb_substr($value, 0, self::HeaderDisplayLength, 'UTF-8').'…';
			}
			$lines[] = Text::sprintf('COM_BFSTOP_SETTINGS_ADDRESS_CHECK_HEADER',
				'<code>'.$escape($name).'</code>', '<code>'.$escape($value).'</code>');
			++$headers;
		}
		if ($headers === 0)
		{
			$lines[] = Text::_('COM_BFSTOP_SETTINGS_ADDRESS_CHECK_NO_HEADER');
		}
		$lines[] = Text::sprintf('COM_BFSTOP_SETTINGS_ADDRESS_CHECK_USED', '<strong><code>'.$escape($used).'</code></strong>');
		return '<ul class="mb-0"><li>'.implode('</li><li>', $lines).'</li></ul>';
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
			'COM_BFSTOP_TEST_NOTIFICATION', false);
	}
}
