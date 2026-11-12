<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Codeling\Plugin\System\Bfstop\Helper\HtaccessHelper;
use Joomla\CMS\Log\Log;

class UnblockHelper
{
	private static function getHtaccessPath()
	{
		$htaccessPath = ParamHelper::get('htaccessPath', 'params', JPATH_ROOT);
		return $htaccessPath === "" ? JPATH_ROOT : $htaccessPath;
	}

	/**
	 * With blocking through .htaccess, the web server keeps rejecting an
	 * address until its line is taken out of the file - the plugin only does
	 * that when it blocks the next address or once a day. So whatever was
	 * unblocked here is taken out right away (if no other block of the
	 * address is still active).
	 */
	public static function removeLiftedHtaccessBlocks($logger)
	{
		if (ParamHelper::get('blockMode', 'params', 'full') !== 'htaccess')
		{
			return;
		}
		$htaccess = new HtaccessHelper(self::getHtaccessPath(), $logger);
		$htaccess->removeLiftedBlocks(new DatabaseHelper($logger));
	}

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
			$htaccess = new HtaccessHelper(self::getHtaccessPath(), null);
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
			$curResult = false;
			try
			{
				$id = (int) $id;
				// only blocks which exist: block ids are handed out in order, so
				// an entry for one which doesn't exist yet would lift a block
				// to come in advance - whoever may unblock could switch the
				// blocking off that way, which takes the permission to change
				// the settings
				$db->setQuery('SELECT COUNT(*) FROM #__bfstop_bannedip WHERE id='.$id);
				if ((int) $db->loadResult() === 0)
				{
					$logger->log("com_bfstop unblock: There is no block $id", Log::INFO);
					continue;
				}
				$sql = 'SELECT * FROM #__bfstop_unblock WHERE block_id='.$id;
				$db->setQuery($sql);
				$unblockEntry = $db->loadObject();
				if ($unblockEntry != null)
				{
					// nothing to do for this one - but the others selected
					// with it still have to be unblocked
					$logger->log("com_bfstop unblock: Block $id was already lifted", Log::INFO);
					continue;
				}
				$unblock = new \stdClass();
				$unblock->block_id = $id;
				$unblock->source = $source; // source of 1 indicates unblock via email
				$unblock->crdate = $unblockDate;
				$curResult = $db->insertObject('#__bfstop_unblock', $unblock);
			}
			catch (\RuntimeException $e)
			{
				$logger->log($e->getMessage(), Log::ERROR);
			}
			// also if the insert threw: that is a failure as well
			$result = $result && $curResult;
			$logger->log("com_bfstop unblock: Inserting unblock ".(($curResult) ? "successful" : "not successful")."!", ($curResult) ? Log::INFO : Log::ERROR);
		}
		return $result;
	}
}
