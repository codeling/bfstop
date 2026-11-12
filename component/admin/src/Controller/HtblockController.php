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
use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
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
		$this->checkToken();
		// this fully overrides FormController::save(), so it doesn't
		// inherit the base class's automatic allowSave()/core.create check.
		// An entry is part of the web server's configuration: it turns
		// addresses away before Joomla runs, so nobody can lift it from
		// within the site who is in it - core.admin as well, like the
		// settings (which choose the file) and the allow list
		$user = Factory::getApplication()->getIdentity();
		if (!$user || !$user->authorise('core.create', 'com_bfstop') || !$user->authorise('core.admin', 'com_bfstop'))
		{
			$this->returnToFormWithMessage('', Text::_('COM_BFSTOP_NOT_AUTHORISED'));
			return false;
		}
		$logger = LogHelper::getLogger();
		$htaccessPath = ParamHelper::get('htaccessPath', 'params', JPATH_ROOT);
		$htaccessPath = $htaccessPath === "" ? JPATH_ROOT : $htaccessPath;
		$htaccess = new HtaccessHelper($htaccessPath, null);
		$model = $this->getModel('block');
		$form = $model->getForm(null, false);
		$input = Factory::getApplication()->getInput();
		$data  = $input->post->get('jform', array(), 'array');
		$validData = $model->validate($form, $data);
		if ($validData === false)
		{
			$errors = $model->getErrors();
			$msg = "";
			foreach ($errors as $error)
			{
				// the messages have been escaped where they were made (they may
				// contain what was typed in), see IpValidateHelper
				$msg .= ($error instanceof \Exception) ? $error->getMessage() : $error;
			}
			$this->returnToFormWithMessage(is_string($data['ipaddress'] ?? null) ? $data['ipaddress'] : '', $msg);
			return false;
		}
		$ipaddress = $validData['ipaddress'];
		$db = new DatabaseHelper($logger);
		// the web server knows nothing of the allow list: a network in the
		// file would also turn away the allowed addresses in it (and an
		// address in an allowed network); null: the list couldn't be read
		$allowed = $db->allowListEntriesOverlapping($ipaddress);
		if ($allowed === null || count($allowed) > 0)
		{
			$logger->log("'$ipaddress' overlaps the allow list (".($allowed === null ? 'which could not be read' :
				implode(', ', $allowed)).")! Will not block it via .htaccess", Log::INFO);
			$this->returnToFormWithMessage($ipaddress, Text::_('COM_BFSTOP_IPADDRESS_ALLOWED'));
			return false;
		}
		if (IpHelper::overlapsTrustedProxy($ipaddress, IpHelper::trustedProxies()))
		{
			// the web server would turn away everybody coming through it
			$this->returnToFormWithMessage($ipaddress, Text::_('COM_BFSTOP_IPADDRESS_TRUSTED_PROXY'));
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
