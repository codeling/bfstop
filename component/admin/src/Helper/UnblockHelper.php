<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\HtaccessHelper;
use Joomla\CMS\Log\Log;

class UnblockHelper
{
	public static function unblockHtaccess($ips, $logger)
	{
		if (!is_array($ips) || sizeof($ips) == 0)
		{
			$logger->log("com_bfstop unblock: Invalid ips given!", Log::ERROR);
			return false;
		}
		$result = true;
		foreach ($ips as $ip)
		{
			$htaccessPath = ParamHelper::get('htaccessPath', 'params', JPATH_ROOT);
			$htaccessPath = $htaccessPath === "" ? JPATH_ROOT : $htaccessPath;
			$htaccess = new HtaccessHelper($htaccessPath, null);
			$curResult = $htaccess->undenyIP($ip);
			$result = $result && $curResult;
			$logger->log("com_bfstop unblock: .htaccess unblock of $ip ".(($curResult) ? "successful" : "not successful")."!",
				($curResult) ? Log::INFO : Log::ERROR);
		}
		return $result;
	}

	public static function unblockDB($db, $ids, $source, $logger)
	{
		if (!is_array($ids) || sizeof($ids) == 0)
		{
			$logger->log("com_bfstop unblock: Invalid parameter IDs given!", Log::ERROR);
			return false;
		}
		$result = true;
		$unblockDate = date('Y-m-d H:i:s');
		foreach ($ids as $id)
		{
			try
			{
				$id = (int) $id;
				$sql = 'SELECT * FROM #__bfstop_unblock WHERE block_id='.$id;
				$db->setQuery($sql);
				$unblockEntry = $db->loadObject();
				if ($unblockEntry != null)
				{
					$logger->log("com_bfstop unblock: Unblock already exists!", Log::ERROR);
					return false;
				}
				$unblock = new \stdClass();
				$unblock->block_id = $id;
				$unblock->source = $source; // source of 1 indicates unblock via email
				$unblock->crdate = $unblockDate;
				$curResult = $db->insertObject('#__bfstop_unblock', $unblock);
				$result = $result && $curResult;
			}
			catch (\RuntimeException $e)
			{
				$logger->log($e->getMessage(), Log::ERROR);
			}
			$logger->log("com_bfstop unblock: Inserting unblock ".(($curResult) ? "successful" : "not successful")."!", ($curResult) ? Log::INFO : Log::ERROR);
		}
		return $result;
	}
}
