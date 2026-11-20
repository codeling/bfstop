<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Service;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Repository\Repositories;
use Joomla\CMS\Log\Log;

/**
 * What the periodic maintenance does to the tables. Each step fails open
 * (see FailurePolicy): what isn't done now is done by the next run.
 */
class Maintenance
{
	private Repositories $repositories;

	public function __construct(Repositories $repositories)
	{
		$this->repositories = $repositories;
	}

	/**
	 * Deletes what is older than $purgeAgeWeeks weeks: failed logins, ended
	 * blocks (with the records of their lifting) and unblock tokens. What the
	 * ended blocks add to the number of an address's offences is kept (see
	 * BlockRepository::purgeEndedBefore()), for the escalation of its next
	 * block.
	 */
	public function purgeOldEntries($purgeAgeWeeks)
	{
		$this->repositories->logger()->log("Purging entries older than $purgeAgeWeeks weeks", Log::INFO);
		// all timestamps are written with PHP's date(), so compare against
		// the same clock instead of the database's NOW(), which may use a
		// different time zone
		$deleteDate = date('Y-m-d H:i:s', time() - ((int) $purgeAgeWeeks) * 7 * 24 * 60 * 60);
		$this->repositories->failedLogins()->purgeBefore($deleteDate);
		$this->repositories->blocks()->purgeEndedBefore($deleteDate);
		$this->repositories->unblockTokens()->purgeBefore($deleteDate);
		// the reverse-DNS cache has an age of its own, see DnsCacheRepository::prune()
	}

	/**
	 * What is not deleted by age, whatever the purge age is set to: it is
	 * kept below an upper bound, or has a lifetime of its own. A visitor can
	 * add a failed login for every request, a username (statistics) for every
	 * attempt, and - with an account - a known address for every address they
	 * log in from.
	 */
	public function keepWithinBounds()
	{
		$this->repositories->failedLogins()->trim();
		$this->repositories->usernameStats()->trim();
		$this->repositories->knownIps()->prune();
		$this->repositories->dnsCache()->prune();
		$this->repositories->unblockTokens()->purgeExpired();
		$this->repositories->blocks()->pruneOffences();
	}
}
