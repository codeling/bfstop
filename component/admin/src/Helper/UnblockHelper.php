<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\NginxDenyFile;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Log\Log;

class UnblockHelper
{
	public static function getHtaccessPath()
	{
		return HtaccessHelper::resolvePath(ParamHelper::get('htaccessPath'));
	}

	/**
	 * With blocking through .htaccess, the web server keeps rejecting an
	 * address until its line is taken out of the file - the plugin only does
	 * that when it blocks the next address or once a day. So whatever was
	 * unblocked here is taken out right away (if no other block of the
	 * address is still active). With another blocking mode, the file may
	 * still hold the entries of the time it blocked: they all come out (see
	 * HtaccessHelper::removeStaleBlocks()).
	 */
	public static function removeLiftedHtaccessBlocks($logger)
	{
		$htaccess = new HtaccessHelper(self::getHtaccessPath(), $logger);
		$repositories = new Repositories($logger);
		$htaccess->removeStaleBlocks($repositories->blocks(),
			ParamHelper::get('blockMode') === 'htaccess');
		// the same for nginx's file, which is written from the block list
		NginxDenyFile::syncForSettings(Settings::stored(), $repositories);
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
}
