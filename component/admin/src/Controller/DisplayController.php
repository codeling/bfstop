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
use Codeling\Component\Bfstop\Administrator\Helper\VersionHelper;
use Codeling\Plugin\System\Bfstop\Helper\HtaccessHelper;
use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;
use Joomla\CMS\Router\Route;

class DisplayController extends BaseController
{
	function display($cachable = false, $urlparams = false)
	{
		$input = Factory::getApplication()->input;
		$view = $input->getCmd('view', 'blocklist');

		$pluginInstalled = $this->checkWhetherPluginInstalled();
		if (!$pluginInstalled)
		{
			return;
		}
		$this->warnIfAdminUserExists();
		$this->warnIfHtAccessNotWorking();
		$this->checkWhetherProxyConfigured();
		$input->set('view', $view);
		parent::display($cachable);
	}

	function warnIfAdminUserExists()
	{
		try
		{
			$db = Factory::getDbo();
			$query = "SELECT COUNT(*) FROM #__users u WHERE u.username='admin'";
			$db->setQuery($query);
			if ($db->loadResult() > 0)
			{
				$application = Factory::getApplication();
				$application->enqueueMessage(Text::_('COM_BFSTOP_WARNING_ADMIN_USER_EXISTS'), 'warning');
			}
		}
		catch (\Exception $e)
		{
			$application = Factory::getApplication();
			$application->enqueueMessage("Database exception occurred: ".$e->getMessage(), 'warning');
		}
	}

	function warnIfHtAccessNotWorking()
	{
		$htaccessPath = ParamHelper::get('htaccessPath', 'params', JPATH_ROOT);
		$htaccessPath = $htaccessPath === "" ? JPATH_ROOT : $htaccessPath;
		$htaccess = new HtaccessHelper($htaccessPath, null);
		$req = $htaccess->checkRequirements();
		if (!$req['apacheserver'] ||
			!$req['found'] ||
			!$req['readable'] ||
			!$req['writeable'])
		// TODO: add check whether .htaccess actually is effective!
		{
			$application = Factory::getApplication();
			$application->enqueueMessage(Text::_('COM_BFSTOP_WARNING_HTACCESS_NOT_WORKING')
				// .'found='.$req['found'].', readable='.$req['readable'].', writeable='.$req['writeable'].', apache='.$req['apacheserver']
				, 'warning');
		}
	}

	function checkWhetherProxyConfigured()
	{
		$useProxy = (bool) ParamHelper::get('useProxy', 'params', false);
		if ($useProxy)
		{
			return;
		}
		foreach (IpHelper::KnownProxyHeaders as $header)
		{
			if (array_key_exists($header, $_SERVER) && $_SERVER[$header] !== '')
			{
				$application = Factory::getApplication();
				$application->enqueueMessage(Text::sprintf('COM_BFSTOP_WARNING_PROXY_NOT_CONFIGURED', Route::_('index.php?option=com_bfstop&view=settings', false)), 'warning');
				return;
			}
		}
	}

	function checkWhetherPluginInstalled()
	{
		try
		{
			$db = Factory::getDbo();
			$query = "SELECT manifest_cache,enabled FROM #__extensions WHERE name='plg_system_bfstop'";
			$db->setQuery($query);
			$plugin = $db->loadObject();
			if (is_null($plugin))
			{
				$application = Factory::getApplication();
				$application->enqueueMessage(Text::_('COM_BFSTOP_WARNING_PLUGIN_NOT_INSTALLED'), 'warning');
				return false;
			}
			$query = "SELECT manifest_cache FROM #__extensions WHERE name='com_bfstop'";
			$db->setQuery($query);
			$component = $db->loadObject();
			if (is_null($component))
			{
				$application = Factory::getApplication();
				$application->enqueueMessage(Text::_('COM_BFSTOP_WARNING_CANNOT_RETRIEVE_COMPONENT_CACHE'), 'warning');
				return false;
			}
			$plugin_version = VersionHelper::getVersion($plugin->manifest_cache);
			$component_version = VersionHelper::getVersion($component->manifest_cache);
			if (!VersionHelper::checkSameMajorMinor($component_version, $plugin_version))
			{
				$application = Factory::getApplication();
				$application->enqueueMessage(Text::_('COM_BFSTOP_WARNING_COMPONENT_PLUGIN_DIFFERENT_VERSION'), 'warning');
				return false;
			}
			if ($plugin->enabled != 1)
			{
				$application = Factory::getApplication();
				$application->enqueueMessage(Text::sprintf('COM_BFSTOP_WARNING_PLUGIN_DISABLED', Route::_('index.php?option=com_plugins&view=plugins', false)), 'warning');
				// this is not a "hard" failure; we can still manage the tables!
				// return false;
			}
			return true;
		}
		catch (\Exception $e)
		{
			$application = Factory::getApplication();
			$application->enqueueMessage("Database exception occurred: ".$e->getMessage(), 'warning');
		}
	}
}
