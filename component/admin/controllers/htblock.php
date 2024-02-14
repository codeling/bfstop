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
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Controller\FormController;
use Joomla\CMS\Router\Route;

require_once(JPATH_ADMINISTRATOR.'/components/com_bfstop/helpers/params.php');
$pluginHelperDir = JPATH_SITE.'/plugins/system/bfstop/helpers/';
require_once($pluginHelperDir.'htaccess.php');
require_once($pluginHelperDir.'db.php');

class BFStopControllerHTBlock extends FormController
{
	public function add()
	{
		$this->setRedirect(
			Route::_('index.php?option=com_bfstop&view=htblock', false)
		);
		return true;	
	}

	public function returnToFormWithMessage($ipaddress, $msg)
	{
		$application = Factory::getApplication();
		$formdata = array("ipaddress" => $ipaddress);
		$application->setUserState('com_bfstop.edit.htblock.data', $formdata);
		$application->enqueueMessage($msg, 'warning');
		$this->setRedirect(
			Route::_('index.php?option=com_bfstop&view=htblock', false)
		);
	}
	public function save($key = null, $urlVar = null)
	{
		$logger = getLogger();
		$htaccessPath = BFStopParamHelper::get('htaccessPath', 'params', JPATH_ROOT);
		$htaccessPath = $htaccessPath === "" ? JPATH_ROOT : $htaccessPath;
		$htaccess = new BFStopHtAccess($htaccessPath, null);
		$model = $this->getModel('block');
		$form = $model->getForm(null, false);
		$input = Factory::getApplication()->input;
		$data  = $input->post->get('jform', array(), 'array');
		$validData = $model->validate($form, $data);
		if ($validData === false)
		{
			$errors = $model->getErrors();
			$msg = "";
			foreach ($errors as $error)
			{
				if ($error instanceof \Exception)
				{
					$msg .= $error->getMessage();
				}
				else
				{
					$msg .= $error;
				}
			}
			$this->returnToFormWithMessage($data['ipaddress'], $msg);
			return false;
		}
		$ipaddress = $validData['ipaddress'];
		$db = new BFStopDBHelper($logger);
		if ($db->isIPOnAllowList($ipaddress))
		{
			$logger->log("IP address '$ipaddress' is on allow list! Will not block it via .htaccess", Log::INFO);
			$this->returnToFormWithMessage($ipaddress, Text::_('COM_BFSTOP_IPADDRESS_ALLOWED'));
			return false;
		}
		$result = $htaccess->denyIP($ipaddress);
		if ($result)
		{
			$logger->log("Added ipaddress '$ipaddress' to .htaccess from backend", Log::INFO);
			$this->setRedirect(
				Route::_('index.php?option=com_bfstop&view=htblocklist', false)
			);
		}
		else
		{
			$this->returnToFormWithMessage($ipaddress, Text::_('COM_BFSTOP_INVALID_IPADDRESS'));
		}
		return $result;
	}
	public function cancel($key = null)
	{
		$application = Factory::getApplication();
		$application->setUserState('com_bfstop.edit.htblock.data', array());
		$this->setRedirect(
			Route::_('index.php?option=com_bfstop&view=htblocklist',false)
		);
	}

}
