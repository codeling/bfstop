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
use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Controller\BaseController;
use Joomla\CMS\Router\Route;

class LogController extends BaseController
{
	/**
	 * Checks the token and the permission to delete; sets the redirect and
	 * returns false if the request has to be refused.
	 */
	private function checkRequest($listUrl)
	{
		$this->checkToken();
		if (!Factory::getApplication()->getIdentity()->authorise('core.delete', 'com_bfstop'))
		{
			$this->setRedirect($listUrl, Text::_('COM_BFSTOP_NOT_AUTHORISED'), 'error');
			return false;
		}
		return true;
	}

	/**
	 * Does what the plugin does once a day: moves a log file which is too
	 * big out of the way, and removes the entries older than the retention.
	 */
	function prune()
	{
		$listUrl = Route::_('index.php?option=com_bfstop&view=log', false);
		if (!$this->checkRequest($listUrl))
		{
			return;
		}
		$keepDays = (int) ParamHelper::get('logKeepDays', 'params', LoggerHelper::DefaultKeepDays);
		if ($keepDays < 1)
		{
			$this->setRedirect($listUrl, Text::sprintf('COM_BFSTOP_LOG_PRUNE_DISABLED',
				Route::_('index.php?option=com_bfstop&view=settings', false)), 'warning');
			return;
		}
		$maxMB = (int) ParamHelper::get('logMaxSize', 'params', LoggerHelper::DefaultMaxSizeMB);
		LoggerHelper::rotateIfTooBig(LoggerHelper::maxBytesFromMegabytes($maxMB));
		$deleted = LoggerHelper::pruneByAge($keepDays);
		LogHelper::getLogger()->log("Manually pruned $deleted log entries older than $keepDays days", Log::INFO);
		$this->setRedirect($listUrl,
			Text::plural('COM_BFSTOP_LOG_PRUNE_N_DELETED', $deleted, $keepDays), 'message');
	}

	function clear()
	{
		$listUrl = Route::_('index.php?option=com_bfstop&view=log', false);
		if (!$this->checkRequest($listUrl))
		{
			return;
		}
		$logger = LogHelper::getLogger();
		LoggerHelper::deleteLogFiles();
		// the new log file starts with a note on what happened to the old one
		$logger->log('The log was cleared manually', Log::INFO);
		$this->setRedirect($listUrl, Text::_('COM_BFSTOP_LOG_CLEARED'), 'message');
	}
}
