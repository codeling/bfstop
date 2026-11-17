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
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Controller\AdminController;
use Joomla\CMS\Router\Route;

class FailedloginlistController extends AdminController
{
	public function getModel($name = 'failedloginlist', $prefix = '', $config = [])
	{
		$model = parent::getModel($name, $prefix, array('ignore_request' => true));
		return $model;
	}

	function purge()
	{
		$this->checkToken();
		$listUrl = Route::_('index.php?option=com_bfstop&view=failedloginlist', false);
		if (!Factory::getApplication()->getIdentity()->authorise('core.delete', 'com_bfstop'))
		{
			$this->setRedirect($listUrl, Text::_('COM_BFSTOP_NOT_AUTHORISED'), 'error');
			return;
		}
		$age = Factory::getApplication()->getInput()->post->getInt('age', 0);
		if ($age < 1)
		{
			$this->setRedirect($listUrl, Text::_('COM_BFSTOP_FAILEDLOGIN_PURGE_INVALID_AGE'), 'error');
			return;
		}
		$logger = LogHelper::getLogger();
		try
		{
			$deleted = $this->getModel('failedloginlist')->purgeOlderThan($age);
			$logger->log("Manually purged $deleted failed login entries older than $age days", Log::INFO);
			$this->setRedirect($listUrl,
				Text::plural('COM_BFSTOP_FAILEDLOGIN_PURGE_N_DELETED', $deleted, $age), 'message');
		}
		catch (\Exception $e)
		{
			$logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			$this->setRedirect($listUrl,
				Text::sprintf('COM_BFSTOP_FAILEDLOGIN_PURGE_FAILED', $e->getMessage()), 'error');
		}
	}
}
