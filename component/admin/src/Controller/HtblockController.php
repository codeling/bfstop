<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Controller;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ActionLogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\UnblockHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Controller\FormController;
use Joomla\CMS\Router\Route;

class HtblockController extends FormController
{
	/**
	 * Whether $user may add an entry to the .htaccess file: it is part of the
	 * web server's configuration, which turns addresses away before Joomla
	 * runs, so nobody in it can lift it from within the site - core.admin as
	 * well as core.create, like the settings (which choose the file) and the
	 * allow list. The toolbars ask this too.
	 */
	public static function mayAdd($user): bool
	{
		return $user && $user->authorise('core.create', 'com_bfstop') && $user->authorise('core.admin', 'com_bfstop');
	}

	public function add()
	{
		$this->setRedirect(
			Route::_('index.php?option=com_bfstop&view=htblock', false)
		);
		return true;
	}

	public function returnToFormWithMessage($ipaddress, $msg)
	{
		$application = $this->app;
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
		// inherit the base class's automatic allowSave()/core.create check
		if (!self::mayAdd($this->app->getIdentity()))
		{
			$this->returnToFormWithMessage('', Text::_('COM_BFSTOP_NOT_AUTHORISED'));
			return false;
		}
		$logger = LogHelper::getLogger();
		$htaccessPath = UnblockHelper::getHtaccessPath();
		$htaccess = new HtaccessHelper($htaccessPath, null);
		// the form of the view, see HtblockModel
		$model = $this->getModel('htblock');
		$form = $model->getForm(array(), false);
		$input = $this->input;
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
		// in the spelling the block list has it, which the file's entries
		// are compared with (see HtaccessHelper::isEntryOf())
		$ipaddress = IpHelper::canonicalEntry($validData['ipaddress']) ?? (string) $validData['ipaddress'];
		$repositories = new Repositories($logger);
		// the web server knows nothing of the allow list: a network in the
		// file would also turn away the allowed addresses in it (and an
		// address in an allowed network); null: the list couldn't be read
		$allowed = $repositories->allowList()->entriesOverlapping($ipaddress);
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
			ActionLogHelper::log('htaccess_added', array('ipaddress' => $ipaddress));
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
		$application = $this->app;
		$application->setUserState('com_bfstop.edit.htblock.data', array());
		$this->setRedirect(
			Route::_('index.php?option=com_bfstop&view=htblocklist', false)
		);
		return true;
	}
}
