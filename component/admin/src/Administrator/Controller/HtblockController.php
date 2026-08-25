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
use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Codeling\Plugin\System\Bfstop\Helper\HtaccessHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Controller\FormController;
use Joomla\CMS\Router\Route;

class HtblockController extends FormController
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
		$logger = LogHelper::getLogger();
		$htaccessPath = ParamHelper::get('htaccessPath', 'params', JPATH_ROOT);
		$htaccessPath = $htaccessPath === "" ? JPATH_ROOT : $htaccessPath;
		$htaccess = new HtaccessHelper($htaccessPath, null);
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
		$db = new DatabaseHelper($logger);
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
			Route::_('index.php?option=com_bfstop&view=htblocklist', false)
		);
	}
}
