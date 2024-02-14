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
use Joomla\CMS\Router\Route;
use Joomla\CMS\MVC\Controller\BaseController;

require_once(JPATH_ADMINISTRATOR.'/components/com_bfstop/helpers/params.php');
$htaccesshelper = JPATH_SITE.'/plugins/system/bfstop/helpers/htaccess.php';
if (file_exists(stream_resolve_include_path($htaccesshelper)))
{
	require_once($htaccesshelper);
}

class BFStopController extends BaseController
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
		$this->checkForAdminUser();

		$this->checkWhetherHtAccessWorks();
		$input->set('view', $view);
		parent::display($cachable);
	}

	function checkForAdminUser()
	{
		try
		{
			$db = Factory::getDBO();
			$query = "SELECT COUNT(*) FROM #__users u WHERE u.username='admin'";
			$db->setQuery($query);
			if ($db->loadResult() > 0)
			{
				$application = Factory::getApplication();
				$application->enqueueMessage(Text::_('COM_BFSTOP_WARNING_ADMIN_USER_EXISTS'), 'warning');
			}
		}
		catch (Exception $e)
		{
			$application = Factory::getApplication();
			$application->enqueueMessage("Database exception occured: ".$e->getMessage(), 'warning');
		}
	}

	function checkWhetherHtAccessWorks()
	{
		$htaccessPath = BFStopParamHelper::get('htaccessPath', 'params', JPATH_ROOT);
		$htaccessPath = $htaccessPath === "" ? JPATH_ROOT : $htaccessPath;
		$htaccess = new BFStopHtAccess($htaccessPath, null);
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

	function checkSameMajorMinor($version1, $version2)
	{
		$ver1arr = explode($version1, ".");
		$ver2arr = explode($version2, ".");
		return count($ver1arr) >= 2 && count($ver2arr) >= 2 && $ver1arr[0] === $ver2arr[0] && $ver1arr[1] == $ver2arr[1];
	}

	function getVersion($manifest_cache)
	{
		$json = json_decode($manifest_cache);
		return (property_exists($json, "version")) ? $json->version : '';
	}

	function checkWhetherPluginInstalled()
	{
		try
		{
			$db = Factory::getDBO();
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
			$plugin_version = $this->getVersion($plugin->manifest_cache);
			$component_version = $this->getVersion($component->manifest_cache);
			if ($this->checkSameMajorMinor($component_version, $plugin_version))
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
		catch (Exception $e)
		{
			$application = Factory::getApplication();
			$application->enqueueMessage("Database exception occured: ".$e->getMessage(), 'warning');
		}
	}
}
