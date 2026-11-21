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
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Controller\BaseController;
use Joomla\CMS\Router\Route;

/**
 * The tasks of the list (see the toolbar of its view): a BaseController, not
 * an AdminController, whose tasks (publish, delete, checkin, ...) call
 * methods a list model hasn't got - an error page instead of an answer.
 */
class UsernamestatsController extends BaseController
{
	public function getModel($name = 'usernamestats', $prefix = '', $config = [])
	{
		$model = parent::getModel($name, $prefix, array('ignore_request' => true));
		return $model;
	}

	public function purge()
	{
		$this->checkToken();
		$listUrl = Route::_('index.php?option=com_bfstop&view=usernamestats', false);
		if (!$this->app->getIdentity()->authorise('core.delete', 'com_bfstop'))
		{
			$this->setRedirect($listUrl, Text::_('COM_BFSTOP_NOT_AUTHORISED'), 'error');
			return;
		}
		$age = $this->input->post->getInt('age', 0);
		if ($age < 1)
		{
			$this->setRedirect($listUrl, Text::_('COM_BFSTOP_USERNAMESTATS_PURGE_INVALID_AGE'), 'error');
			return;
		}
		$logger = LogHelper::getLogger();
		try
		{
			$deleted = $this->getModel('usernamestats')->purgeNotSeenFor($age);
			$logger->log("Manually deleted statistics of $deleted usernames not seen for $age days", Log::INFO);
			ActionLogHelper::log('usernamestats_purged', array('count' => $deleted, 'days' => $age));
			$this->setRedirect($listUrl,
				Text::plural('COM_BFSTOP_USERNAMESTATS_PURGE_N_DELETED', $deleted, $age), 'message');
		}
		catch (\Throwable $e)
		{
			$logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			$this->setRedirect($listUrl,
				Text::sprintf('COM_BFSTOP_USERNAMESTATS_PURGE_FAILED', $e->getMessage()), 'error');
		}
	}
}
