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
use Codeling\Plugin\System\Bfstop\Helper\NotifierHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\FormController;
use Joomla\CMS\Router\Route;

class SettingsController extends FormController
{
	public function __construct($config = array(), $factory = null, $app = null, $input = null)
	{
		parent::__construct($config, $factory, $app, $input);
		// there is no per-record "settings" item to route to/from; this is a
		// singleton screen editing the plugin's own #__extensions row.
		$this->view_item = 'settings';
		$this->view_list = 'settings';
	}

	public function getModel($name = 'settings', $prefix = 'bfstopmodel', $config = array())
	{
		$config['ignore_request'] = true;
		$model = parent::getModel($name, $prefix, $config);
		return $model;
	}

	public function save($key = null, $urlVar = null)
	{
		$this->checkToken();
		if (!$this->allowSave())
		{
			$this->setRedirect(Route::_('index.php?option=com_bfstop&view=settings', false),
				Text::_('JERROR_ALERTNOAUTHOR'), 'error');
			return false;
		}
		return parent::save($key, $urlVar);
	}

	protected function allowSave()
	{
		$user = Factory::getApplication()->getIdentity();
		return $user && $user->authorise('core.admin', 'com_bfstop');
	}

	protected function getRedirectToItemAppend($recordId = null, $urlVar = 'id')
	{
		return '';
	}

	public function testNotify()
	{
		$this->checkToken();
		$emailAddress = ParamHelper::get('emailaddress', 'params', '');
		$userID = (int) ParamHelper::get('userID', 'params', -1);
		$userGroup = (int) ParamHelper::get('userGroup', 'params', -1);
		$groupNotifEnabled = (bool) ParamHelper::get('groupNotificationEnabled', 'params', false);
		$logger = LogHelper::getLogger();
		$db = new DatabaseHelper($logger);
		$notifier = new NotifierHelper($logger, $db,
			$emailAddress,
			$userID,
			$userGroup,
			$groupNotifEnabled);
		if (count($notifier->getNotifyAddresses()) == 0)
		{
			$result = false;
		}
		else
		{
			$subject = Text::sprintf('TEST_MAIL_SUBJECT', $notifier->getSiteName());
			$body = Text::sprintf('TEST_MAIL_BODY', $notifier->getSiteName());
			$result = $notifier->sendMail($subject, $body, $notifier->getNotifyAddresses());
		}
		$success = ($result === true);
		// redirect back to settings view:
		$this->setRedirect(Route::_('index.php?option=com_bfstop&view=settings', false),
			$success
				? Text::_('TEST_NOTIFICATION_SUCCESS')
				: Text::sprintf('TEST_NOTIFICATION_FAILED', $result),
			$result
				? 'notice'
				: 'error'
		);
	}
}
