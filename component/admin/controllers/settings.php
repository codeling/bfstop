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
use Joomla\CMS\MVC\Controller\AdminController;
use Joomla\CMS\Router\Route;

require_once(JPATH_ADMINISTRATOR.'/components/com_bfstop/helpers/params.php');

class BFStopControllerSettings extends AdminController
{
	public function getModel($name = 'settings', $prefix = 'bfstopmodel', $config=array())
	{
		$config['ignore_request'] = true;
		$model = parent::getModel($name, $prefix, $config);
		return $model;
	}

	public function testNotify()
	{
		$emailAddress = BFStopParamHelper::get('emailaddress', 'params', '');
		$userID = (int)BFStopParamHelper::get('userID', 'params', -1);
		$userGroup = (int)BFStopParamHelper::get('userGroup', 'params', -1);
		$groupNotifEnabled = (bool)BFStopParamHelper::get('groupNotificationEnabled', 'params', false);
		$logger = getLogger();
		$db  = new BFStopDBHelper($logger);
		$notifier = new BFStopNotifier($logger, $db,
			$emailAddress,
			$userID,
			$userGroup,
			$groupNotifEnabled);
		if (count($notifier->getNotifyAddresses()) == 0)
		{
			$result = false;
		} else {
			$subject = Text::sprintf('TEST_MAIL_SUBJECT', $notifier->getSiteName());
			$body = Text::sprintf('TEST_MAIL_BODY', $notifier->getSiteName());
			$application = Factory::getApplication();
			$result = $notifier->sendMail($subject, $body, $notifier->getNotifyAddresses());
		}
		$success = ($result === true);
		// redirect back to settings view:
		$this->setRedirect(Route::_('index.php?option=com_bfstop&view=settings',false),
			$success
				? Text::_('TEST_NOTIFICATION_SUCCESS')
				: Text::sprintf('TEST_NOTIFICATION_FAILED', $result),
			$result
				? 'notice'
				: 'error'
		);
	}
}
