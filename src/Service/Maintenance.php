<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Service;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Extension\Bfstop;
use Codeling\Plugin\System\Bfstop\Helper\HtaccessHelper;
use Codeling\Plugin\System\Bfstop\Helper\LockHelper;
use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use Codeling\Plugin\System\Bfstop\Repository\Repositories;
use Joomla\CMS\Log\Log;
use Joomla\Registry\Registry;

/**
 * The periodic maintenance - of the tables, the .htaccess file and the log -
 * and the conversion of the stored addresses after an update, and when they
 * are due. Each step fails open (see FailurePolicy): what isn't done now is
 * done by the next run.
 */
class Maintenance
{
	// the daily maintenance runs at most this often, in seconds
	public const Interval = 86400;

	private Repositories $repositories;

	public function __construct(Repositories $repositories)
	{
		$this->repositories = $repositories;
	}

	/**
	 * Does what is due, by the plugin's settings $params (which keep when it
	 * was last done; the values it changes are changed in $params as well).
	 */
	public function runDue(Registry $params, $now = null)
	{
		// lookups of the block and allow list need the addresses in canonical
		// form, which entries of earlier versions are not in: once, before the
		// first lookup of this version (every request has one, later). The
		// installer script can't do this reliably - the class of the previous
		// version may be loaded still
		if (!$params->get('addressesCanonical', false))
		{
			$this->canonicalizeStoredAddressesOnce($params);
		}
		$now = $now ?? time();
		if ($now > ((int) $params->get('lastPurge', 0) + self::Interval))
		{
			$this->runDaily($params, $now);
		}
	}

	/** The daily maintenance. */
	private function runDaily(Registry $params, $now)
	{
		// before the purge, which deletes the blocks that ran out long ago:
		// without them, their entries couldn't be told from those added by hand
		$this->tidyHtaccess(HtaccessHelper::resolvePath((string) $params->get('htaccessPath', '')),
			$params->get('blockMode', 'full') === 'htaccess');
		$purgeAge = (int) $params->get('deleteOld', Bfstop::DefaultSettings['deleteOld']);
		if ($purgeAge > 0)
		{
			$this->purgeOldEntries($purgeAge);
		}
		// regardless of the purge age setting: these are not deleted by age
		$this->keepWithinBounds();
		LoggerHelper::pruneByAge((int) $params->get('logKeepDays', LoggerHelper::DefaultKeepDays));
		$params->set('lastPurge', $now);
		$this->repositories->pluginSettings()->set('lastPurge', (int) $now);
	}

	/**
	 * The daily maintenance of the .htaccess file in $directory, whatever the
	 * blocking mode is now ($throughFile: blocking through the file):
	 *
	 * - a block section of an earlier version grants access (see
	 *   HtaccessHelper::LegacyLines), and one which doesn't let the unblock
	 *   page through makes the links of unblock emails lead nowhere: it is
	 *   written in the current form (the update can't, see updatescript.php);
	 * - the web server knows nothing of durations and unblocks: with blocking
	 *   through the file, the addresses whose blocks are over come out of it;
	 *   with another blocking mode, every address the plugin has blocked -
	 *   the entries are left from the time the file blocked, and would turn
	 *   the addresses away for good, see HtaccessHelper::removeStaleBlocks().
	 */
	public function tidyHtaccess($directory, $throughFile)
	{
		$logger = $this->repositories->logger();
		$htaccess = new HtaccessHelper($directory, $logger);
		if (!is_file($htaccess->getFileName()))
		{
			return;
		}
		if (!$htaccess->upgradeFormat())
		{
			$logger->log('Could not write the block section of '.$htaccess->getFileName().' in its current form '.
				'- make the file writable: one of an earlier version lets everybody who isn\'t blocked past the other '.
				'access controls of the directory, and without the current form, the links of unblock emails can\'t be '.
				'followed', Log::ERROR);
		}
		if ($htaccess->removeStaleBlocks($this->repositories->blocks(), $throughFile) === false)
		{
			$logger->log('Could not take the addresses the plugin blocked out of '.$htaccess->getFileName().
				': the web server goes on refusing them - make the file writable', Log::ERROR);
		}
	}

	/**
	 * Brings the stored addresses into canonical form, if no other request
	 * did or does: every request starts out with the settings as they were
	 * when it began, so after the update all requests arriving before the
	 * first of them is done would see the setting unset, and each would go
	 * through the whole block and allow list (and update the same rows) - on
	 * a busy site with a long list, many at once. The first takes a lock; the
	 * others go on without waiting (their lookups may miss an entry which
	 * isn't converted yet, as they would have before the update). Once it has
	 * the lock, a request checks the stored setting again, as another one may
	 * have finished in the meantime. If no lock can be taken (no writable
	 * temporary directory), it is done without one: it can be run more than
	 * once, it only costs time.
	 */
	private function canonicalizeStoredAddressesOnce(Registry $params)
	{
		$logger = $this->repositories->logger();
		$lockFile = HtaccessHelper::lockDirectory().'/bfstop-canonicalize-'.LockHelper::siteHash().'.lock';
		$handle = @fopen($lockFile, 'c');
		if ($handle !== false && !flock($handle, LOCK_EX | LOCK_NB))
		{
			fclose($handle);
			$logger->log('Another request is converting the stored addresses, not waiting for it', Log::DEBUG);
			return;
		}
		try
		{
			$settings = $this->repositories->pluginSettings();
			if (!$settings->get('addressesCanonical', false))
			{
				$changed = $this->canonicalizeStoredAddresses();
				$settings->set('addressesCanonical', 1);
				$logger->log('Converted '.$changed.' stored address(es) to canonical form', Log::INFO);
			}
			$params->set('addressesCanonical', 1);
		}
		finally
		{
			if ($handle !== false)
			{
				flock($handle, LOCK_UN);
				fclose($handle);
			}
		}
	}

	/**
	 * Deletes what is older than $purgeAgeWeeks weeks: failed logins, ended
	 * blocks (with the records of their lifting) and unblock tokens.
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
	}

	/**
	 * Brings the addresses in the block and allow list into canonical form
	 * (IpHelper::canonicalEntry()), which lookups depend on.
	 *
	 * @return int the number of entries changed
	 */
	public function canonicalizeStoredAddresses()
	{
		return $this->repositories->blocks()->canonicalize() + $this->repositories->allowList()->canonicalize();
	}
}
