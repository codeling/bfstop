<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Service;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\LockHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
use Joomla\CMS\Log\Log;

class BlockService
{
	private Repositories $repositories;

	public function __construct(Repositories $repositories)
	{
		$this->repositories = $repositories;
	}

	// lock files for the block decision, see withLock(): the tracked
	// addresses are spread over this many, so there is no file per address
	private const LockStripes = 64;

	/**
	 * Runs $decision while holding the lock for the tracked address $key.
	 * Parallel failed logins of one client which all reach the threshold
	 * would otherwise all find it not blocked yet and each block it: several
	 * blocks at once - each counted as an earlier offence, so a single burst
	 * could make the block permanent (maxBlocksBefore), or multiply its
	 * duration - and a mail for each. If no lock can be taken (no writable
	 * temporary directory), it runs without one.
	 */
	public function withLock($key, callable $decision)
	{
		$stripe = hexdec(substr(md5((string) $key), 0, 4)) % self::LockStripes;
		$lockFile = HtaccessHelper::lockDirectory().'/bfstop-block-'.LockHelper::siteHash().'-'.$stripe.'.lock';
		// not for ever: see LockHelper
		$handle = LockHelper::acquire($lockFile, HtaccessHelper::LockWaitSeconds);
		if (!$handle)
		{
			$this->repositories->logger()->log('Could not lock '.$lockFile.
				($handle === null ? ' within '.HtaccessHelper::LockWaitSeconds.' seconds' : '').
				', blocking without it', Log::WARNING);
			return $decision();
		}
		try
		{
			return $decision();
		}
		finally
		{
			LockHelper::release($handle);
		}
	}

	/**
	 * Blocks the client of $logEntry as $policy decides, if it isn't blocked
	 * yet; to be called under withLock().
	 *
	 * @param object      $logEntry      the failed login which led to the block
	 * @param string|null $clientAddress see BlockPolicy::decide()
	 * @return array|null id, duration and targetedOtherAccounts of the new
	 *                    block; null if nothing was blocked
	 */
	public function blockAsDecided($logEntry, $clientAddress, BlockPolicy $policy)
	{
		$logger = $this->repositories->logger();
		$decision = $policy->decide($logEntry, $clientAddress);
		if ($decision === null)
		{
			return null;
		}
		if ($decision['throughFile'])
		{
			// the file only holds what is still blocked
			(new HtaccessHelper($decision['htaccessPath'], $logger))->removeLiftedBlocks($this->repositories->blocks());
		}
		$id = $this->block($logEntry, $decision['duration'], $decision['htaccess'], $decision['htaccessPath']);
		if ($id < 1)
		{
			// nothing is blocked: neither tell the administrators that
			// something was, nor mail an unblock link for a block which
			// doesn't exist
			$logger->log('Could not block IP address '.$logEntry->ipaddress.', see the previous errors', Log::ERROR);
			return null;
		}
		$logger->log('Inserted IP address '.$logEntry->ipaddress.' into block list', Log::INFO);
		return array('id' => $id, 'duration' => $decision['duration'],
			'targetedOtherAccounts' => $decision['targetedOtherAccounts']);
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
