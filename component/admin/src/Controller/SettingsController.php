<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Controller;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\HtaccessCheckHelper;
use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\ParamHelper;
use Codeling\Component\Bfstop\Administrator\Helper\UnblockHelper;
use Codeling\Library\Bfstop\Helper\NotifierHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
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

	public function getModel($name = 'settings', $prefix = '', $config = array())
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

	protected function allowSave($data = array(), $key = 'id')
	{
		$user = $this->app->getIdentity();
		return $user && $user->authorise('core.admin', 'com_bfstop');
	}

	/**
	 * FormController's other tasks ("settings.edit", "settings.add",
	 * "settings.reload") ask these, and by default they are answered with
	 * core.edit and core.create: the settings are for who may change them.
	 */
	protected function allowEdit($data = array(), $key = 'id')
	{
		return $this->allowSave($data, $key);
	}

	protected function allowAdd($data = array())
	{
		return $this->allowSave($data);
	}

	/**
	 * There is nothing to open for editing: the settings are one page, shown
	 * by the view. FormController::edit() would check out the record the
	 * request names - with this model's table any row of Joomla's extensions
	 * table, for a plain GET request without a token - and leave it locked
	 * for the other administrators.
	 */
	public function edit($key = null, $urlVar = null)
	{
		$this->setRedirect(Route::_('index.php?option=com_bfstop&view=settings', false));
		return $this->allowSave();
	}

	/**
	 * Leaves the page without saving: forgets what was typed in (kept after
	 * a save which was refused). FormController::cancel() would also check
	 * in the record the request names.
	 */
	public function cancel($key = null)
	{
		$this->checkToken();
		$this->app->setUserState('com_bfstop.edit.settings.data', null);
		$this->setRedirect(Route::_('index.php?option=com_bfstop&view=settings', false));
		return true;
	}

	protected function getRedirectToItemAppend($recordId = null, $urlVar = 'id')
	{
		return '';
	}

	/**
	 * Checks whether the web server honours the block section of the
	 * .htaccess file (see HtaccessCheckHelper), for the directory of the
	 * saved settings.
	 */
	public function checkHtaccess()
	{
		$this->checkToken();
		$settingsUrl = Route::_('index.php?option=com_bfstop&view=settings', false);
		if (!$this->allowSave())
		{
			$this->setRedirect($settingsUrl, Text::_('COM_BFSTOP_NOT_AUTHORISED'), 'error');
			return;
		}
		$dir = UnblockHelper::getHtaccessPath();
		list($message, $type) = self::htaccessCheckMessage(HtaccessCheckHelper::run($dir), $dir);
		$this->setRedirect($settingsUrl, $message, $type);
	}

	/**
	 * The message and its type for the result of HtaccessCheckHelper::run()
	 * for the directory $dir.
	 *
	 * @return string[] array(message, type)
	 */
	public static function htaccessCheckMessage(array $result, string $dir): array
	{
		list($outcome, $detail) = $result;
		$where = htmlspecialchars($dir, ENT_QUOTES, 'UTF-8');
		switch ($outcome)
		{
			case HtaccessCheckHelper::Effective:
				return array(Text::sprintf('COM_BFSTOP_HTACCESS_CHECK_EFFECTIVE', $where), 'message');
			case HtaccessCheckHelper::Ignored:
				return array(Text::sprintf('COM_BFSTOP_HTACCESS_CHECK_IGNORED', $where), 'warning');
			case HtaccessCheckHelper::Broken:
				return array(Text::sprintf('COM_BFSTOP_HTACCESS_CHECK_BROKEN', $where), 'error');
		}
		$reason = in_array($detail, array('outside', 'write', 'request'), true)
			? Text::_('COM_BFSTOP_HTACCESS_CHECK_REASON_'.strtoupper($detail))
			: Text::sprintf('COM_BFSTOP_HTACCESS_CHECK_REASON_STATUS', htmlspecialchars($detail, ENT_QUOTES, 'UTF-8'));
		return array(Text::sprintf('COM_BFSTOP_HTACCESS_CHECK_UNKNOWN', $where, $reason), 'warning');
	}

	public function testNotify()
	{
		$this->checkToken();
		// part of the settings, so reserved for who may change them: the
		// mail goes to the notification addresses configured there
		if (!$this->allowSave())
		{
			$this->setRedirect(Route::_('index.php?option=com_bfstop&view=settings', false),
				Text::_('COM_BFSTOP_NOT_AUTHORISED'), 'error');
			return;
		}
		$emailAddress = ParamHelper::get('emailaddress');
		$userID = (int) ParamHelper::get('userID');
		$userGroup = (int) ParamHelper::get('userGroup');
		$groupNotifEnabled = (bool) ParamHelper::get('groupNotificationEnabled');
		$logger = LogHelper::getLogger();
		$notifier = new NotifierHelper($logger, new Repositories($logger),
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
			$subject = Text::sprintf('COM_BFSTOP_TEST_MAIL_SUBJECT', $notifier->getSiteName());
			$body = Text::sprintf('COM_BFSTOP_TEST_MAIL_BODY', $notifier->getSiteName());
			$result = $notifier->sendMail($subject, $body, $notifier->getNotifyAddresses());
		}
		$success = ($result === true);
		// redirect back to settings view:
		$this->setRedirect(Route::_('index.php?option=com_bfstop&view=settings', false),
			$success
				? Text::_('COM_BFSTOP_TEST_NOTIFICATION_SUCCESS')
				: Text::sprintf('COM_BFSTOP_TEST_NOTIFICATION_FAILED', $result),
			$success
				? 'message'
				: 'error'
		);
	}
}
