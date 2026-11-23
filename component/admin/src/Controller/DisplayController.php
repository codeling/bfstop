<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Controller;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\ParamHelper;
use Codeling\Component\Bfstop\Administrator\Helper\UnblockHelper;
use Codeling\Component\Bfstop\Administrator\Helper\VersionHelper;
use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\BlockPolicy;
use Codeling\Library\Bfstop\Service\Setup\ProxyDetector;
use Codeling\Library\Bfstop\Service\Setup\ProxyMismatch;
use Codeling\Library\Bfstop\Service\Setup\SetupState;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;
use Joomla\CMS\Router\Route;
use Joomla\Database\DatabaseInterface;

class DisplayController extends BaseController
{
	public function display($cachable = false, $urlparams = [])
	{
		$input = $this->input;
		$view = $input->getCmd('view', 'blocklist');

		$pluginInstalled = $this->checkWhetherPluginInstalled();
		if ($pluginInstalled === false)
		{
			return $this;
		}
		$this->warnIfAdminUserExists();
		$this->warnIfHtAccessNotWorking($view);
		if ($view !== 'setup')
		{
			// the assistant shows both itself
			$this->showSetupBanners($pluginInstalled === 'enabled');
		}
		if ($view !== 'settings')
		{
			// the settings page says it itself, see its view
			$this->warnIfUnblockLinksNeedLiveSite();
		}
		$input->set('view', $view);
		return parent::display($cachable);
	}

	public function warnIfAdminUserExists()
	{
		try
		{
			$db = Factory::getContainer()->get(DatabaseInterface::class);
			// LOWER: also catch "Admin" etc. on PostgreSQL, which (unlike
			// MySQL's default collations) compares case-sensitively
			$query = "SELECT COUNT(*) FROM #__users u WHERE LOWER(u.username)='admin'";
			$db->setQuery($query);
			if ($db->loadResult() > 0)
			{
				$application = $this->app;
				$application->enqueueMessage(Text::_('COM_BFSTOP_WARNING_ADMIN_USER_EXISTS'), 'warning');
			}
		}
		catch (\Throwable $e)
		{
			$application = $this->app;
			$application->enqueueMessage("Database exception occurred: ".$e->getMessage(), 'warning');
		}
	}

	/**
	 * Says why blocking through the .htaccess file won't work, if it doesn't
	 * look as if it would: where it is the blocking mode, and on the pages
	 * of the file's entries.
	 *
	 * @param string $view the page shown
	 */
	public function warnIfHtAccessNotWorking($view = '')
	{
		if (ParamHelper::get('blockMode') !== 'htaccess' && $view !== 'htblocklist' && $view !== 'htblock')
		{
			return;
		}
		$htaccessPath = UnblockHelper::getHtaccessPath();
		$htaccess = new HtaccessHelper($htaccessPath, null);
		$req = $htaccess->checkRequirements();
		$modes = array(Text::_('COM_BFSTOP_SETTINGS_BLOCK_MODE_HTACCESS'), Text::_('COM_BFSTOP_SETTINGS_BLOCK_MODE_FULL'));
		if ($req['server'] === HtaccessHelper::ServerNginx)
		{
			// the file itself doesn't matter: nginx never reads it
			$this->app->enqueueMessage(Text::sprintf('COM_BFSTOP_WARNING_HTACCESS_NGINX', ...$modes), 'warning');
			return;
		}
		if ($req['server'] === HtaccessHelper::ServerLiteSpeed)
		{
			$this->app->enqueueMessage(Text::sprintf('COM_BFSTOP_WARNING_HTACCESS_LITESPEED', ...$modes), 'warning');
		}
		// whether the web server honours the section takes requests to find
		// out: the settings page has a button for it (settings.checkHtaccess)
		if (!in_array($req['server'], array(HtaccessHelper::ServerApache, HtaccessHelper::ServerLiteSpeed), true) ||
			!$req['found'] ||
			!$req['readable'] ||
			!$req['writeable'])
		{
			$this->app->enqueueMessage(Text::_('COM_BFSTOP_WARNING_HTACCESS_NOT_WORKING'), 'warning');
		}
	}

	/**
	 * Unblock links were chosen (before this version checked it, or
	 * $live_site was removed since), but they need $live_site: the plugin
	 * sends none, see BlockPolicy::effectiveNotifyBlockedUser().
	 */
	public function warnIfUnblockLinksNeedLiveSite()
	{
		$setting = (int) ParamHelper::get('notifyBlockedUser');
		if (BlockPolicy::effectiveNotifyBlockedUser($setting, BlockPolicy::hasLiveSite()) !== $setting)
		{
			$this->app->enqueueMessage(Text::sprintf('COM_BFSTOP_WARNING_NOTIFY_ANY_WITHOUT_LIVE_SITE',
				Route::_('index.php?option=com_bfstop&view=settings', false)), 'warning');
		}
	}

	/**
	 * The banners of the setup (for who may change the settings, who can do
	 * something about them): protection isn't active or the setup isn't
	 * complete, and the mismatches of the proxy settings and this request
	 * which haven't been dismissed (see ProxyMismatch) - the same the quick
	 * icon of the Home Dashboard shows. With links to the assistant: the
	 * messages can hold no form, so "This is expected" is on its proxy page.
	 *
	 * @param bool $pluginEnabled whether the system plugin is enabled
	 */
	public function showSetupBanners(bool $pluginEnabled)
	{
		$user = $this->app->getIdentity();
		if (!$user || !$user->authorise('core.admin', 'com_bfstop') || !class_exists(SetupState::class))
		{
			return;
		}
		$setup = SetupState::load((new Repositories(LogHelper::getLogger()))->state());
		$assistant = Route::_('index.php?option=com_bfstop&view=setup', false);
		if (!$pluginEnabled)
		{
			$this->app->enqueueMessage(Text::sprintf('COM_BFSTOP_BANNER_NOT_ACTIVE', $assistant), 'error');
		}
		elseif (!$setup->isCompleted())
		{
			$this->app->enqueueMessage(Text::sprintf('COM_BFSTOP_BANNER_SETUP_INCOMPLETE', $assistant), 'warning');
		}
		$proxyPage = Route::_('index.php?option=com_bfstop&view=setup&page=proxy', false);
		foreach (ProxyMismatch::open(ProxyMismatch::check($_SERVER, ProxyDetector::proxySettings(Settings::stored()),
			(bool) $this->app->get('behind_loadbalancer', 0), $setup)) as $mismatch)
		{
			$text = $mismatch['code'] === ProxyMismatch::LoadBalancer
				? Text::_('COM_BFSTOP_SETUP_LOADBALANCER_'.strtoupper($mismatch['hint']))
				: Text::_('COM_BFSTOP_SETUP_MISMATCH_'.strtoupper($mismatch['code']));
			$this->app->enqueueMessage($text.' '.Text::sprintf('COM_BFSTOP_BANNER_PROXY_CHECK', $proxyPage),
				$mismatch['information'] ? 'notice' : 'warning');
		}
	}

	/**
	 * Whether the system plugin is installed, in a version which fits the
	 * component, and enabled.
	 *
	 * @return string|false 'enabled' or 'disabled'; false if it isn't
	 *                      installed or doesn't fit (said in a message)
	 */
	public function checkWhetherPluginInstalled()
	{
		try
		{
			$db = Factory::getContainer()->get(DatabaseInterface::class);
			$query = $db->createQuery()
				->select($db->quoteName(array('manifest_cache', 'enabled')))
				->from($db->quoteName('#__extensions'))
				->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
				->where($db->quoteName('folder') . ' = ' . $db->quote('system'))
				->where($db->quoteName('element') . ' = ' . $db->quote('bfstop'));
			$db->setQuery($query);
			$plugin = $db->loadObject();
			if (is_null($plugin))
			{
				$application = $this->app;
				$application->enqueueMessage(Text::_('COM_BFSTOP_WARNING_PLUGIN_NOT_INSTALLED'), 'warning');
				return false;
			}
			$query = $db->createQuery()
				->select($db->quoteName('manifest_cache'))
				->from($db->quoteName('#__extensions'))
				->where($db->quoteName('type') . ' = ' . $db->quote('component'))
				->where($db->quoteName('element') . ' = ' . $db->quote('com_bfstop'));
			$db->setQuery($query);
			$component = $db->loadObject();
			if (is_null($component))
			{
				$application = $this->app;
				$application->enqueueMessage(Text::_('COM_BFSTOP_WARNING_CANNOT_RETRIEVE_COMPONENT_CACHE'), 'warning');
				return false;
			}
			$plugin_version = VersionHelper::getVersion($plugin->manifest_cache);
			$component_version = VersionHelper::getVersion($component->manifest_cache);
			if (!VersionHelper::checkSameMajorMinor($component_version, $plugin_version))
			{
				$application = $this->app;
				$application->enqueueMessage(Text::_('COM_BFSTOP_WARNING_COMPONENT_PLUGIN_DIFFERENT_VERSION'), 'warning');
				return false;
			}
			if ($plugin->enabled != 1)
			{
				// this is not a "hard" failure; we can still manage the tables!
				// Who may change the settings is sent to the setup assistant,
				// which activates the plugin (see showSetupBanners())
				$user = $this->app->getIdentity();
				if (!$user || !$user->authorise('core.admin', 'com_bfstop'))
				{
					$this->app->enqueueMessage(Text::_('COM_BFSTOP_WARNING_PLUGIN_DISABLED'), 'warning');
				}
				return 'disabled';
			}
			return 'enabled';
		}
		catch (\Throwable $e)
		{
			$application = $this->app;
			$application->enqueueMessage("Database exception occurred: ".$e->getMessage(), 'warning');
			return false;
		}
	}
}
