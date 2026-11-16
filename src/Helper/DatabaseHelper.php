<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Repository\AllowListRepository;
use Codeling\Plugin\System\Bfstop\Repository\BlockRepository;
use Codeling\Plugin\System\Bfstop\Repository\DnsCacheRepository;
use Codeling\Plugin\System\Bfstop\Repository\FailedLoginRepository;
use Codeling\Plugin\System\Bfstop\Repository\KnownIpRepository;
use Codeling\Plugin\System\Bfstop\Repository\PluginSettingsRepository;
use Codeling\Plugin\System\Bfstop\Repository\UnblockTokenRepository;
use Codeling\Plugin\System\Bfstop\Repository\UserRepository;
use Codeling\Plugin\System\Bfstop\Repository\UsernameStatsRepository;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\Database\DatabaseInterface;

class DatabaseHelper
{
	private $db;
	private $logger;
	private $repositories = array();

	// 10 years in minutes. For all intents here sufficiently large to stand for "forever":
	public static $UNLIMITED_DURATION = 5256000;

	// how long an emailed unblock token can be used
	public static $UNBLOCK_TOKEN_VALID_DAYS = UnblockTokenRepository::ValidDays;


	// upper bound for the rows of the failed logins, however the purge age is
	// set: a visitor can add one for every request, from as many addresses as
	// they like
	public static $FAILED_LOGIN_MAX_ROWS = 200000;

	// upper bound for the rows of the username statistics, which (unlike
	// the failed logins) are not purged by age: an attacker can make up as
	// many usernames as they like
	public static $USERNAME_STATS_MAX_ROWS = 10000;

	// known IP addresses (where a user logged in from) are forgotten after
	// this long without a login from them, and the table is kept below this
	// number of rows, oldest first: a visitor with an account can log in from
	// as many addresses as they like
	public static $KNOWN_IP_MAX_AGE_DAYS = 365;
	public static $KNOWN_IP_MAX_ROWS = 100000;

	// how long a reverse-DNS lookup result is trusted before being redone -
	// keeps the (potentially slow) gethostbyaddr() call to at most once per
	// IP per TTL window, see issue #103
	public static $DNS_CACHE_TTL_DAYS = 7;

	// upper bound for the rows of the reverse-DNS cache: it has a row per
	// address, and a client with an IPv6 network can fail every login from
	// another one
	public static $DNS_CACHE_MAX_ROWS = 10000;

	public function getClientString($id)
	{
		// the client id of the application: site 0, administrator 1, api 3
		switch ((int) $id)
		{
			case 0:
				return 'Frontend';
			case 3:
				return 'API';
			default:
				return 'Backend';
		}
	}

	public function __construct(LoggerHelper $logger)
	{
		$this->db = Factory::getContainer()->get(DatabaseInterface::class);
		$this->logger = $logger;
	}

	/**
	 * The repository of the given class (one per class and helper). Each
	 * reads and writes its table(s) and decides how it fails, see
	 * FailurePolicy; this class puts what the plugin does together from them.
	 */
	private function repository($class)
	{
		if (!isset($this->repositories[$class]))
		{
			$this->repositories[$class] = new $class($this->db, $this->logger);
		}
		return $this->repositories[$class];
	}

	public function blocks(): BlockRepository
	{
		return $this->repository(BlockRepository::class);
	}

	public function allowList(): AllowListRepository
	{
		return $this->repository(AllowListRepository::class);
	}

	public function failedLogins(): FailedLoginRepository
	{
		return $this->repository(FailedLoginRepository::class);
	}

	public function usernameStats(): UsernameStatsRepository
	{
		return $this->repository(UsernameStatsRepository::class);
	}

	public function unblockTokens(): UnblockTokenRepository
	{
		return $this->repository(UnblockTokenRepository::class);
	}

	public function knownIps(): KnownIpRepository
	{
		return $this->repository(KnownIpRepository::class);
	}

	public function dnsCache(): DnsCacheRepository
	{
		return $this->repository(DnsCacheRepository::class);
	}

	public function users(): UserRepository
	{
		return $this->repository(UserRepository::class);
	}

	public function pluginSettings(): PluginSettingsRepository
	{
		return $this->repository(PluginSettingsRepository::class);
	}

	// ----- failed logins

	public function getNumberOfFailedLogins($interval, $ipaddress, $logtime)
	{
		if ($interval <= 0)
		{
			$this->logger->log("Invalid interval $interval");
		}
		return $this->failedLogins()->countUnhandledFromAddress($interval, $ipaddress, $logtime);
	}

	public function getNumberOfFailedLoginsForUsername($interval, $username, $logtime)
	{
		if ($interval <= 0)
		{
			$this->logger->log("Invalid interval $interval");
		}
		return $this->failedLogins()->countUnhandledForUsername($interval, $username, $logtime);
	}

	/**
	 * The number of failed logins (by anybody) in the $minutes up to $time.
	 */
	public function countFailedLoginsInWindow($time, $minutes)
	{
		return $this->failedLogins()->countInWindow($time, $minutes);
	}

	/**
	 * The number of blocks made in the $minutes up to $time.
	 */
	public function countBlocksInWindow($time, $minutes)
	{
		return $this->blocks()->countCreatedInWindow($time, $minutes);
	}

	public function getFailedLoginsInLastHour()
	{
		return $this->failedLogins()->countInLastHour();
	}

	public function getNumberOfPreviousBlocks($ipaddress)
	{
		return $this->blocks()->countPrevious($ipaddress);
	}

	public function getFormattedFailedList($ipAddress, $curTime, $interval)
	{
		$entries = $this->failedLogins()->listFromAddress($ipAddress, $curTime, $interval);
		$result = str_pad(Text::_('PLG_SYSTEM_BFSTOP_USERNAME'), 25)." ".
				str_pad(Text::_('PLG_SYSTEM_BFSTOP_IPADDRESS'), 15)." ".
				str_pad(Text::_('PLG_SYSTEM_BFSTOP_DATETIME'), 20)." ".
				str_pad(Text::_('PLG_SYSTEM_BFSTOP_ORIGIN'), 8)."\n".
				str_repeat("-", 97)."\n";
		foreach ($entries as $entry)
		{
			$result .= str_pad(LoggerHelper::singleLine($entry->username), 25)." ".
				str_pad($entry->ipaddress, 15)." ".
				str_pad($entry->logtime, 20)." ".
				str_pad($this->getClientString($entry->origin), 8)."\n";
		}
		return $result;
	}

	public function insertFailedLogin($logEntry)
	{
		$this->failedLogins()->add($logEntry);
		$this->usernameStats()->recordAttempt($logEntry->username, $logEntry->logtime);
	}

	public function setFailedLoginHandled($info, $restrictOnUsername)
	{
		$this->failedLogins()->markHandled($info->ipaddress, $restrictOnUsername ? $info->username : null);
	}

	/**
	 * Whether the failed logins which count towards blocking $ipaddress (those
	 * within $interval minutes before $logtime that haven't been handled yet)
	 * include attempts against an existing account other than $username.
	 * Attempts against usernames which don't exist don't count: they can't
	 * get an attacker anywhere. If that can't be determined, it is assumed
	 * that there are (fail-closed: no unblock link goes out then).
	 */
	public function hasFailedLoginsForOtherAccounts($interval, $ipaddress, $username, $logtime)
	{
		$attempted = $this->failedLogins()->unhandledUsernamesFromAddress($interval, $ipaddress, $logtime);
		if ($attempted === null)
		{
			return true;
		}
		foreach ($attempted as $name)
		{
			if (mb_strtolower($name) !== mb_strtolower($username) && $this->accountExists($name))
			{
				return true;
			}
		}
		return false;
	}

	// ----- blocks and the allow list

	/**
	 * Brings the addresses in the block and allow list into canonical form
	 * (IpHelper::canonicalEntry()), which lookups depend on.
	 *
	 * @return int the number of entries changed
	 */
	public function canonicalizeStoredAddresses()
	{
		return $this->blocks()->canonicalize() + $this->allowList()->canonicalize();
	}

	/**
	 * IDs of all currently active blocks matching the given IP address,
	 * whether as single address or as part of a blocked IPv4/IPv6 subnet.
	 */
	public function getActiveBlockIds($ipaddress)
	{
		return $this->getActiveBlockIdsOrNull($ipaddress) ?? array();
	}

	/**
	 * getActiveBlockIds(), but null if the block list could not be read -
	 * for whoever must not take that for "not blocked".
	 *
	 * @return int[]|null
	 */
	public function getActiveBlockIdsOrNull($ipaddress)
	{
		return $this->blocks()->activeIdsFor($ipaddress);
	}

	/**
	 * The addresses which have been blocked, but are not any more: the block
	 * has run out or was lifted, and no other block of the same address is
	 * active. For blocking through the web server's configuration, which
	 * knows nothing about durations.
	 */
	public function getAddressesWithoutActiveBlock()
	{
		return $this->blocks()->addressesWithoutActiveBlock();
	}

	/**
	 * Every address and network of the block list, whether its block is
	 * active or not.
	 *
	 * @return string[]|null null if the block list could not be read
	 */
	public function getBlockedAddresses()
	{
		return $this->blocks()->allAddresses();
	}

	public function isIPBlocked($ipaddress)
	{
		return (count($this->getActiveBlockIds($ipaddress)) > 0);
	}

	/**
	 * Count a rejected request against the given blocks and remember when it
	 * happened (issue #219), so that stale blocks can be identified.
	 */
	public function recordBlockedAttempt($blockIds)
	{
		$this->blocks()->recordAttempt($blockIds);
	}

	public function isIPOnAllowList($ipaddress)
	{
		return $this->allowList()->contains($ipaddress);
	}

	/**
	 * The entries of the allow list which overlap the address or network
	 * $entry (see IpHelper::overlapping()): what a block of $entry in the
	 * .htaccess file would turn away as well. If the allow list can't be
	 * read, every entry is assumed to overlap.
	 *
	 * @return string[]|null null if the allow list could not be read
	 */
	public function allowListEntriesOverlapping($entry)
	{
		return $this->allowList()->entriesOverlapping($entry);
	}

	public function blockIP($logEntry, $duration, $usehtaccess, $htaccessPath)
	{
		$id = $this->blocks()->add($logEntry->ipaddress, $duration);
		if ($id < 0)
		{
			return -1;
		}
		try
		{
			$this->failedLogins()->markHandled($logEntry->ipaddress);
			if ($usehtaccess)
			{
				$htaccess = new HtaccessHelper($htaccessPath, $this->logger);
				$this->logger->log('Blocking '.$logEntry->ipaddress.' through '.$htaccess->getFileName(), Log::INFO);
				$htaccess->denyIP($logEntry->ipaddress);
			}
			return $id;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return -1;
		}
	}

	// ----- unblock tokens

	/**
	 * What is stored of an unblock token, see UnblockTokenRepository::hash().
	 * com_bfstop's TokenunblockModel uses this too.
	 */
	public static function hashToken($token)
	{
		return UnblockTokenRepository::hash($token);
	}

	/**
	 * @param string      $token    the token to put into the link; only its hash is stored
	 * @param string|null $username the user the link is sent to, if any
	 * @return string|null $token, or null if it could not be stored
	 */
	public function getNewUnblockToken($id, $token, $username = null)
	{
		return $this->unblockTokens()->add($id, $token, $username);
	}

	/**
	 * Whether $token is an unexpired unblock token issued for one of the
	 * given blocks. Used to decide if a blocked client may reach the unblock
	 * page.
	 */
	public function unblockTokenValidForBlocks($token, array $blockIds)
	{
		return $this->unblockTokens()->validForBlocks($token, $blockIds);
	}

	/**
	 * Whether an unblock link which can still be used was sent to $username.
	 */
	public function hasCurrentUnblockToken($username)
	{
		return $this->unblockTokens()->hasCurrentFor($username);
	}

	public function unblockTokenExists($token)
	{
		return $this->unblockTokens()->exists($token);
	}

	// ----- accounts

	/**
	 * Whether $login is the username or the email address of an existing
	 * account (Joomla! can be set up to accept either at the login).
	 */
	public function accountExists($login)
	{
		return $this->users()->accountExists($login);
	}

	public function getUserEmailByID($uid)
	{
		return $this->users()->emailById($uid);
	}

	public function getUserEmailByName($username)
	{
		return $this->users()->emailByUsername($username);
	}

	public function getUserGroupEmail($gid)
	{
		return $this->users()->emailsOfGroup($gid);
	}

	// ----- logins

	/**
	 * @param object      $info           ipaddress (the client's address) and username
	 * @param string|null $trackedAddress the key this client is tracked by (see
	 *                                    IpHelper::trackedAddress(): for IPv6 its
	 *                                    network), if not its address. Failed
	 *                                    logins are recorded under this key
	 * @param string|null $trustedAddress the key under which the login is
	 *                                    remembered as one the user has made
	 *                                    from here (IpHelper::trustPrefixLength():
	 *                                    never coarser than a /64), if not
	 *                                    $trackedAddress
	 */
	public function successfulLogin($info, $trackedAddress = null, $trustedAddress = null)
	{
		$key = $trackedAddress ?? $info->ipaddress;
		$this->failedLogins()->markHandled($key, $info->username);
		$this->knownIps()->remember($trustedAddress ?? $key, $info->username);
	}

	/**
	 * Whether $username has logged in successfully from $ipaddress before,
	 * see KnownIpRepository::hasLoggedInFrom().
	 */
	public function hasLoggedInFrom($ipaddress, $username, $ipv6PrefixLength)
	{
		return $this->knownIps()->hasLoggedInFrom($ipaddress, $username, $ipv6PrefixLength);
	}

	// ----- reverse DNS cache

	/**
	 * Returns false if there is no (unexpired) cached entry for this IP - the
	 * caller should do a live lookup and cache it via cacheHostname().
	 * Returns null if the cache confirms this IP has no PTR record, or the
	 * cached hostname string otherwise. false/null/string are deliberately
	 * distinct: null must not be confused with "not cached".
	 */
	public function getCachedHostname($ipaddress)
	{
		return $this->dnsCache()->get($ipaddress, self::$DNS_CACHE_TTL_DAYS);
	}

	public function cacheHostname($ipaddress, $hostname)
	{
		$this->dnsCache()->put($ipaddress, $hostname);
	}

	// ----- maintenance

	public function purgeOldEntries($purgeAgeWeeks)
	{
		$this->logger->log("Purging entries older than $purgeAgeWeeks weeks", Log::INFO);
		// all timestamps are written with PHP's date(), so compare against
		// the same clock instead of the database's NOW(), which may use a
		// different time zone
		$deleteDate = date('Y-m-d H:i:s', time() - ((int) $purgeAgeWeeks) * 7 * 24 * 60 * 60);
		$this->failedLogins()->purgeBefore($deleteDate);
		$this->blocks()->purgeEndedBefore($deleteDate);
		$this->unblockTokens()->purgeBefore($deleteDate);
		// the reverse-DNS cache has an age of its own, see pruneDnsCache()
	}

	/**
	 * Remembers when the periodic maintenance last ran.
	 */
	public function saveLastPurge($timestamp)
	{
		$this->savePluginSetting('lastPurge', (int) $timestamp);
	}

	/**
	 * A setting as it is stored now - the plugin's $params are what was stored
	 * when the request began.
	 */
	public function getPluginSetting($name, $default = null)
	{
		return $this->pluginSettings()->get($name, $default);
	}

	/**
	 * Stores one value in the plugin's settings (bookkeeping of the plugin,
	 * not set on the settings page), see PluginSettingsRepository::set().
	 */
	public function savePluginSetting($name, $value)
	{
		$this->pluginSettings()->set($name, $value);
	}

	/**
	 * Deletes the unblock tokens which can't be used any more.
	 */
	public function purgeExpiredUnblockTokens()
	{
		$this->unblockTokens()->purgeExpired();
	}

	/**
	 * Deletes the cached reverse-DNS results which have expired and, oldest
	 * first, as many more as needed to keep at most $maxRows. Run by the daily
	 * maintenance whatever the purge age is set to: with the reverse-DNS risk
	 * signal on, a visitor adds a row for every address they fail a login
	 * from.
	 */
	public function pruneDnsCache($maxRows = null)
	{
		$this->dnsCache()->prune(self::$DNS_CACHE_TTL_DAYS, $maxRows ?? self::$DNS_CACHE_MAX_ROWS);
	}

	/**
	 * Forgets the addresses users logged in from longer ago than $maxAgeDays,
	 * and, oldest first, as many more as needed to keep at most $maxRows.
	 */
	public function pruneKnownIps($maxAgeDays = null, $maxRows = null)
	{
		$this->knownIps()->prune($maxAgeDays ?? self::$KNOWN_IP_MAX_AGE_DAYS, $maxRows ?? self::$KNOWN_IP_MAX_ROWS);
	}

	/**
	 * Keeps the failed logins below $maxRows by deleting the oldest ones.
	 */
	public function trimFailedLogins($maxRows = null)
	{
		$this->failedLogins()->trim($maxRows ?? self::$FAILED_LOGIN_MAX_ROWS);
	}

	/**
	 * Keeps the username statistics below $maxRows by deleting the entries of
	 * the usernames with the fewest attempts, the longest ago first.
	 */
	public function trimUsernameStats($maxRows = null)
	{
		$this->usernameStats()->trim($maxRows ?? self::$USERNAME_STATS_MAX_ROWS);
	}
}
