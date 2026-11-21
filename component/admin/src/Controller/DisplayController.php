<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Controller;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ParamHelper;
use Codeling\Component\Bfstop\Administrator\Helper\UnblockHelper;
use Codeling\Component\Bfstop\Administrator\Helper\VersionHelper;
use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Service\BlockPolicy;
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
		if (!$pluginInstalled)
		{
			return $this;
		}
		$this->warnIfAdminUserExists();
		$this->warnIfHtAccessNotWorking($view);
		$this->checkWhetherProxyConfigured();
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
		// TODO: add check whether .htaccess actually is effective!
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

	public function checkWhetherProxyConfigured()
	{
		$useProxy = (bool) ParamHelper::get('useProxy');
		if ($useProxy)
		{
			return;
		}
		foreach (IpHelper::KnownProxyHeaders as $header)
		{
			if (array_key_exists($header, $_SERVER) && $_SERVER[$header] !== '')
			{
				$application = $this->app;
				$application->enqueueMessage(Text::sprintf('COM_BFSTOP_WARNING_PROXY_NOT_CONFIGURED', Route::_('index.php?option=com_bfstop&view=settings', false)), 'warning');
				return;
			}
		}
	}

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
				$application = $this->app;
				$application->enqueueMessage(Text::sprintf('COM_BFSTOP_WARNING_PLUGIN_DISABLED', Route::_('index.php?option=com_plugins&view=plugins', false)), 'warning');
				// this is not a "hard" failure; we can still manage the tables!
				// return false;
			}
			return true;
		}
		catch (\Throwable $e)
		{
			$application = $this->app;
			$application->enqueueMessage("Database exception occurred: ".$e->getMessage(), 'warning');
			return false;
		}
	}
}
