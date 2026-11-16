<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Service;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\HtaccessHelper;
use Codeling\Plugin\System\Bfstop\Repository\Repositories;
use Joomla\CMS\Log\Log;

class BlockService
{
	private Repositories $repositories;

	public function __construct(Repositories $repositories)
	{
		$this->repositories = $repositories;
	}

	/**
	 * Blocks the address of a failed login: adds the block, lets the failed
	 * logins of the address stop counting, and - with blocking through
	 * .htaccess - writes the address into the file.
	 *
	 * @param object $logEntry the failed login which led to the block
	 * @return int the id of the block, -1 if it could not be added
	 */
	public function block($logEntry, $duration, $usehtaccess, $htaccessPath)
	{
		$logger = $this->repositories->logger();
		$id = $this->repositories->blocks()->add($logEntry->ipaddress, $duration);
		if ($id < 0)
		{
			return -1;
		}
		try
		{
			$this->repositories->failedLogins()->markHandled($logEntry->ipaddress);
			if ($usehtaccess)
			{
				$htaccess = new HtaccessHelper($htaccessPath, $logger);
				$logger->log('Blocking '.$logEntry->ipaddress.' through '.$htaccess->getFileName(), Log::INFO);
				$htaccess->denyIP($logEntry->ipaddress);
			}
			return $id;
		}
		catch (\Exception $e)
		{
			$logger->log('Blocking '.$logEntry->ipaddress.' failed: '.$e->getMessage(), Log::ERROR);
			return -1;
		}
	}
}
