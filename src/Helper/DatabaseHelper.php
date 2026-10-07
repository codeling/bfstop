<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

use Joomla\CMS\Cache\CacheControllerFactoryInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;

class DatabaseHelper
{
	private $db;
	private $logger;

	// 10 years in minutes. For all intents here sufficiently large to stand for "forever":
	public static $UNLIMITED_DURATION = 5256000;

	// how long an emailed unblock token can be used; com_bfstop's
	// TokenunblockModel::TokenValidDays must stay in sync with this
	public static $UNBLOCK_TOKEN_VALID_DAYS = 3;

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

	public function getClientString($id)
	{
		return ($id == 0) ? 'Frontend' : 'Backend';
	}

	// $time (as written by date("Y-m-d H:i:s")) moved back by $minutes;
	// computed in PHP so that no database-specific date arithmetic (like
	// MySQL's DATE_SUB) is needed, see issue #206
	private static function minutesBefore($time, $minutes)
	{
		return date("Y-m-d H:i:s", strtotime($time) - ((int)$minutes) * 60);
	}

	// SQL expression for $dateExpr + $minutesExpr minutes, for the cases
	// where the number of minutes comes from a column and can therefore not
	// be computed in PHP. Neither DATE_ADD nor Joomla's
	// DatabaseQuery::dateAdd() work on PostgreSQL for this (issue #206)
	private function addMinutesSql($dateExpr, $minutesExpr)
	{
		if ($this->db->getServerType() === 'postgresql')
		{
			return '('.$dateExpr.' + '.$minutesExpr." * INTERVAL '1 minute')";
		}
		return 'DATE_ADD('.$dateExpr.', INTERVAL '.$minutesExpr.' MINUTE)';
	}

	public function __construct(LoggerHelper $logger)
	{
		$this->db = Factory::getDbo();
		$this->logger = $logger;
	}

	public function eventsInInterval(
		$interval,
		$time,
		$additionalWhere,
		$table = '#__bfstop_failedlogin',
		$timecol = 'logtime')
	{
		try
		{
			if ($interval <= 0)
			{
				$this->logger->log("Invalid interval $interval");
			}
			// check if in the last $interval hours, $number incidents have occured already:
			$sql = "SELECT COUNT(*) FROM ".$table." t ".
				"WHERE t.".$timecol.
				" between ".
				$this->db->quote(self::minutesBefore($time, $interval)).
				" AND ".
				$this->db->quote($time).
				" ".$additionalWhere;
			$this->db->setQuery($sql);
			$numberOfEvents = ((int)$this->db->loadResult());
			return $numberOfEvents;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return 0;
		}
	}

	public function getNumberOfFailedLogins($interval, $ipaddress, $logtime)
	{
		return $this->eventsInInterval($interval, $logtime,
			'AND ipaddress = '.$this->db->quote($ipaddress).
			' AND handled = 0',
			'#__bfstop_failedlogin',
			'logtime');
	}

	public function getNumberOfFailedLoginsForUsername($interval, $username, $logtime)
	{
		// deliberately not filtered by ipaddress - this aggregates failed
		// attempts against this username across every source IP, so that a
		// distributed attack spreading attempts across many IPs against one
		// account is still caught (see issue #76 / OWASP guidance on
		// account-scoped lockout counters)
		return $this->eventsInInterval($interval, $logtime,
			'AND username = '.$this->db->quote($username).
			' AND handled = 0',
			'#__bfstop_failedlogin',
			'logtime');
	}

	public function getFailedLoginsInLastHour()
	{
		try
		{
			$nowDateTime = date("Y-m-d H:i:s");
			$sql = "SELECT COUNT(*) FROM #__bfstop_failedlogin ".
				"WHERE logtime > ".
					$this->db->quote(self::minutesBefore($nowDateTime, 60));
			$this->db->setQuery($sql);
			return $this->db->loadResult();
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return 0;
		}
	}

	public function getNumberOfPreviousBlocks($ipaddress)
	{
		$interval = self::$UNLIMITED_DURATION;
		$logtime = date("Y-m-d H:i:s");
		return $this->eventsInInterval($interval, $logtime,
			'AND ipaddress = '.$this->db->quote($ipaddress).
			' AND NOT EXISTS (SELECT 1 FROM #__bfstop_unblock u '.
			' WHERE t.id=u.block_id AND source=0)',
			'#__bfstop_bannedip', 'crdate');
	}

	public function getFormattedFailedList($ipAddress, $curTime, $interval)
	{
		try
		{
			$sql = "SELECT * FROM #__bfstop_failedlogin t where ipaddress=".
				$this->db->quote($ipAddress).
				" AND t.logtime".
				" between ".$this->db->quote(self::minutesBefore($curTime, $interval)).
				" AND ".
				$this->db->quote($curTime);
			$this->db->setQuery($sql);
			$entries = $this->db->loadObjectList();
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
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return '';
		}
	}

	/**
	 * Loads the rows of $table (aliased t, needs id and ipaddress columns)
	 * which match the given IP address, either literally or as part of a
	 * stored IPv4/IPv6 subnet (CIDR notation). Only the literal match is done
	 * in SQL; subnet entries are matched in PHP (IpHelper::isInSubnet), which
	 * works the same on every database - the previous SQL implementation
	 * relied on MySQL-only functions (INET_ATON, INET6_ATON, LOCATE, REGEXP,
	 * ...), see issue #206, and was the source of #117, #134 and #142.
	 */
	private function loadMatchingEntries($ipaddress, $table, $additionalWhere, $action)
	{
		try
		{
			// LOWER: IPv6 addresses may be stored in upper case; MySQL's
			// default collations compare case-insensitively, PostgreSQL doesn't
			$sql = "SELECT t.id, t.ipaddress FROM ".$table." t WHERE ".
				"((t.ipaddress NOT LIKE '%/%' AND LOWER(t.ipaddress) = LOWER(".$this->db->quote($ipaddress)."))".
				" OR t.ipaddress LIKE '%/%')".
				$additionalWhere;
			$this->db->setQuery($sql);
			$entries = array();
			foreach ($this->db->loadObjectList() as $entry)
			{
				if (strpos($entry->ipaddress, '/') !== false &&
					!IpHelper::isInSubnet($ipaddress, $entry->ipaddress))
				{
					continue;
				}
				$this->logger->log($action." because of entry: ".
					"id=".$entry->id.", ".
					"ipaddress=".$entry->ipaddress,
					Log::DEBUG);
				$entries[] = $entry;
			}
			return $entries;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return array();
		}
	}

	/**
	 * IDs of all currently active blocks matching the given IP address,
	 * whether as single address or as part of a blocked IPv4/IPv6 subnet.
	 */
	public function getActiveBlockIds($ipaddress)
	{
		$activeWhere = " AND (t.duration=0 OR ".
			$this->addMinutesSql('t.crdate', 't.duration')." >= ".
			$this->db->quote(date("Y-m-d H:i:s")).")".
			" AND NOT EXISTS (SELECT 1 FROM #__bfstop_unblock u WHERE t.id = u.block_id)";
		$ids = array();
		foreach ($this->loadMatchingEntries($ipaddress, '#__bfstop_bannedip', $activeWhere, "Blocked") as $entry)
		{
			$ids[] = (int)$entry->id;
		}
		return $ids;
	}

	/**
	 * The addresses which have been blocked, but are not any more: the block
	 * has run out or was lifted, and no other block of the same address is
	 * active. For blocking through the web server's configuration, which
	 * knows nothing about durations.
	 */
	public function getAddressesWithoutActiveBlock()
	{
		try
		{
			$now = $this->db->quote(date("Y-m-d H:i:s"));
			$active = "(c.duration=0 OR ".$this->addMinutesSql('c.crdate', 'c.duration')." >= $now)".
				" AND NOT EXISTS (SELECT 1 FROM #__bfstop_unblock cu WHERE cu.block_id = c.id)";
			$this->db->setQuery("SELECT DISTINCT b.ipaddress FROM #__bfstop_bannedip b WHERE NOT EXISTS ".
				"(SELECT 1 FROM #__bfstop_bannedip c WHERE c.ipaddress = b.ipaddress AND $active)");
			return $this->db->loadColumn();
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return array();
		}
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
		if (count($blockIds) === 0)
		{
			return;
		}
		try
		{
			$query = $this->db->getQuery(true)
				->update($this->db->quoteName('#__bfstop_bannedip'))
				->set($this->db->quoteName('attempts').' = '.$this->db->quoteName('attempts').' + 1')
				->set($this->db->quoteName('last_attempt').' = '.$this->db->quote(date("Y-m-d H:i:s")))
				->where($this->db->quoteName('id').' IN ('.implode(',', array_map('intval', $blockIds)).')');
			$this->db->setQuery($query);
			$this->db->execute();
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}

	public function isIPOnAllowList($ipaddress)
	{
		return count($this->loadMatchingEntries($ipaddress, '#__bfstop_allowlist', '', "Allowed")) > 0;
	}

	public function blockIP($logEntry, $duration, $usehtaccess, $htaccessPath)
	{
		try
		{
			$blockEntry = new \stdClass();
			$blockEntry->ipaddress = $logEntry->ipaddress;
			$blockEntry->crdate = date("Y-m-d H:i:s");
			$blockEntry->duration = $duration;
			if (!$this->db->insertObject('#__bfstop_bannedip', $blockEntry, 'id'))
			{
				$this->logger->log('Insert block entry failed!', Log::ERROR);
				return -1;
			}
			$this->setFailedLoginHandled($logEntry, false);
			if ($usehtaccess)
			{
				$htaccess = new HtaccessHelper($htaccessPath, $this->logger);
				$this->logger->log('Blocking '.$logEntry->ipaddress.' through '.$htaccess->getFileName(), Log::INFO);
				$htaccess->denyIP($logEntry->ipaddress);
			}
			return $blockEntry->id;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return -1;
		}
	}

	/**
	 * @param string|null $username the user the link is sent to, if any
	 */
	public function getNewUnblockToken($id, $token, $username = null)
	{
		try
		{
			$tokenEntry = new \stdClass();
			$tokenEntry->token = $token;
			$tokenEntry->block_id = $id;
			$tokenEntry->crdate = date("Y-m-d H:i:s");
			$tokenEntry->username = $username;
			if (!$this->db->insertObject('#__bfstop_unblock_token', $tokenEntry))
			{
				// maybe check if duplicate token (=PRIMARY KEY violation) and retry?
				$this->logger->log('Insert unblock token failed!', Log::ERROR);
				$tokenEntry->token = null;
			}
			return $tokenEntry->token;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return null;
		}
	}

	/**
	 * Whether $token is an unexpired unblock token issued for one of the
	 * given blocks. Used to decide if a blocked client may reach the unblock
	 * page: a token that belongs to a different IP address's block, or one
	 * that has outlived its validity, must not work as a pass for this one.
	 */
	public function unblockTokenValidForBlocks($token, array $blockIds)
	{
		if ($token === '' || count($blockIds) === 0)
		{
			return false;
		}
		try
		{
			$sql = "SELECT block_id, crdate FROM #__bfstop_unblock_token WHERE token=".
				$this->db->quote($token);
			$this->db->setQuery($sql);
			$row = $this->db->loadAssoc();
			if ($row === null || !in_array((int) $row['block_id'], $blockIds, true))
			{
				return false;
			}
			$created = strtotime($row['crdate']);
			return $created !== false &&
				(time() - $created) <= (self::$UNBLOCK_TOKEN_VALID_DAYS * 86400);
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return false;
		}
	}

	/**
	 * Whether an unblock link which can still be used was sent to $username:
	 * one that hasn't expired and wasn't used (a used token is deleted).
	 */
	public function hasCurrentUnblockToken($username)
	{
		try
		{
			$this->db->setQuery("SELECT COUNT(*) FROM #__bfstop_unblock_token".
				" WHERE LOWER(username) = LOWER(".$this->db->quote($username).")".
				" AND crdate >= ".$this->db->quote(date("Y-m-d H:i:s",
					time() - self::$UNBLOCK_TOKEN_VALID_DAYS * 86400)));
			return ((int) $this->db->loadResult()) > 0;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return true;
		}
	}

	public function unblockTokenExists($token)
	{
		try
		{
			$sql = "SELECT token FROM #__bfstop_unblock_token WHERE token=".
				$this->db->quote($token);
			$this->db->setQuery($sql);
			$result = $this->db->loadResult();
			return $result != null;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return false;
		}
	}

	private function getUserEmailWhere($where)
	{
		try
		{
			$sql = "select email from #__users where $where LIMIT 1";
			$this->db->setQuery($sql);
			return $this->db->loadResult();
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return '';
		}
	}

	/**
	 * Whether $login is the username or the email address of an existing
	 * account (Joomla! can be set up to accept either at the login).
	 */
	public function accountExists($login)
	{
		try
		{
			// LOWER: Joomla treats usernames case-insensitively on login
			// (MySQL's default collations do, PostgreSQL's don't)
			$quoted = "LOWER(".$this->db->quote($login).")";
			$this->db->setQuery("SELECT COUNT(*) FROM #__users WHERE LOWER(username) = ".$quoted.
				" OR LOWER(email) = ".$quoted);
			return ((int) $this->db->loadResult()) > 0;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return false;
		}
	}

	/**
	 * Whether the failed logins which count towards blocking $ipaddress (those
	 * within $interval minutes before $logtime that haven't been handled yet)
	 * include attempts against an existing account other than $username.
	 * Attempts against usernames which don't exist don't count: they can't
	 * get an attacker anywhere. If that can't be determined, it is assumed
	 * that there are.
	 */
	public function hasFailedLoginsForOtherAccounts($interval, $ipaddress, $username, $logtime)
	{
		try
		{
			$this->db->setQuery("SELECT DISTINCT username FROM #__bfstop_failedlogin".
				" WHERE ipaddress = ".$this->db->quote($ipaddress).
				" AND handled = 0 AND logtime BETWEEN ".
				$this->db->quote(self::minutesBefore($logtime, $interval)).
				" AND ".$this->db->quote($logtime));
			foreach ($this->db->loadColumn() as $attempted)
			{
				if (mb_strtolower($attempted) !== mb_strtolower($username) &&
					$this->accountExists($attempted))
				{
					return true;
				}
			}
			return false;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return true;
		}
	}

	public function getUserEmailByID($uid)
	{
		return $this->getUserEmailWhere("id=".((int)$uid));
	}

	public function getUserEmailByName($username)
	{
		return $this->getUserEmailWhere("username=".$this->db->quote($username));
	}

	public function getUserGroupEmail($gid)
	{
		try
		{
			$sql = "SELECT email from #__users u ".
				"LEFT JOIN #__user_usergroup_map g ".
				"ON u.id = g.user_id ".
				"WHERE g.group_id = ".((int)($gid));
			$this->db->setQuery($sql);
			$dbrows = $this->db->loadAssocList();
			$emailAddresses = array();
			foreach ($dbrows as $row)
			{
				$emailAddresses[] = $row['email'];
			}
			return $emailAddresses;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return array();
		}
	}

	public function insertFailedLogin($logEntry)
	{
		try
		{
			$this->db->insertObject('#__bfstop_failedlogin', $logEntry, 'id');
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
		$this->recordUsernameAttempt($logEntry->username, $logEntry->logtime);
	}

	/**
	 * Count a failed login for the given username in the per-username
	 * statistics (issue #136). Unlike the failed login entries themselves,
	 * these statistics are not removed by the automatic purge.
	 */
	private function recordUsernameAttempt($username, $logtime)
	{
		try
		{
			$time = $this->db->quote($logtime);
			$sql = 'INSERT INTO #__bfstop_username_stats'.
				' (username, attempts, first_attempt, last_attempt) VALUES ('.
				$this->db->quote($username).', 1, '.$time.', '.$time.')';
			// upsert: ON DUPLICATE KEY UPDATE is MySQL-only (issue #206)
			if ($this->db->getServerType() === 'postgresql')
			{
				$sql .= ' ON CONFLICT (username) DO UPDATE SET'.
					' attempts=#__bfstop_username_stats.attempts+1, last_attempt='.$time;
			}
			else
			{
				$sql .= ' ON DUPLICATE KEY UPDATE attempts=attempts+1, last_attempt='.$time;
			}
			$this->db->setQuery($sql);
			$this->db->execute();
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}

	public function setFailedLoginHandled($info, $restrictOnUsername)
	{
		try
		{
			$sql = 'UPDATE #__bfstop_failedlogin SET handled=1'.
				' WHERE ipaddress='.$this->db->quote($info->ipaddress).
				' AND handled=0';
			if ($restrictOnUsername)
			{
				$sql .= ' AND username='.$this->db->quote($info->username);
			}
			$this->db->setQuery($sql);
			$this->db->execute();
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}

	/**
	 * @param object      $info           ipaddress (the client's address) and username
	 * @param string|null $trackedAddress the key this client is tracked by (see
	 *                                    IpHelper::trackedAddress(): for IPv6 its
	 *                                    network), if not its address. Failed
	 *                                    logins are recorded, and logins
	 *                                    remembered, under this key
	 */
	public function successfulLogin($info, $trackedAddress = null)
	{
		$key = $trackedAddress ?? $info->ipaddress;
		$handled = new \stdClass();
		$handled->ipaddress = $key;
		$handled->username = $info->username;
		$this->setFailedLoginHandled($handled, true);
		$this->recordKnownIpUsername($key, $info->username);
	}

	/**
	 * Whether $username has logged in successfully from $ipaddress before.
	 *
	 * Logins are remembered under the key the client is tracked by (see
	 * IpHelper::trackedAddress()): an IPv4 address itself, an IPv6 address by
	 * its network, as IPv6 clients commonly switch addresses within it. So
	 * is a login from any address of the network a login from this one.
	 */
	public function hasLoggedInFrom($ipaddress, $username, $ipv6PrefixLength)
	{
		try
		{
			$key = IpHelper::trackedAddress($ipaddress, $ipv6PrefixLength);
			$user = "LOWER(".$this->db->quote($username).")";
			$this->db->setQuery("SELECT COUNT(*) FROM #__bfstop_knownip WHERE ".
				"ipaddress IN (".$this->db->quote($key).", ".$this->db->quote($ipaddress).")".
				" AND LOWER(username) = ".$user);
			if (((int) $this->db->loadResult()) > 0)
			{
				return true;
			}
			if (strpos($ipaddress, ':') === false)
			{
				return false;
			}
			// IPv6: look for entries under another spelling of the address,
			// or recorded at another granularity (the setting was changed)
			$this->db->setQuery("SELECT ipaddress FROM #__bfstop_knownip WHERE LOWER(username) = ".$user);
			$ipBin = @inet_pton($ipaddress);
			foreach ($this->db->loadColumn() as $known)
			{
				if (strpos($known, '/') !== false)
				{
					$match = IpHelper::isInSubnet($ipaddress, $known);
				}
				else
				{
					$knownBin = @inet_pton($known);
					$match = $knownBin !== false &&
						($knownBin === $ipBin || IpHelper::trackedAddress($known, $ipv6PrefixLength) === $key);
				}
				if ($match)
				{
					return true;
				}
			}
			return false;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return false;
		}
	}

	/**
	 * Returns false if there is no (unexpired) cached entry for this IP - the
	 * caller should do a live lookup and cache it via cacheHostname().
	 * Returns null if the cache confirms this IP has no PTR record, or the
	 * cached hostname string otherwise. false/null/string are deliberately
	 * distinct: null must not be confused with "not cached".
	 */
	public function getCachedHostname($ipaddress)
	{
		try
		{
			$sql = "SELECT hostname, checked_at FROM #__bfstop_dnscache WHERE ".
				"ipaddress = ".$this->db->quote($ipaddress);
			$this->db->setQuery($sql);
			$row = $this->db->loadAssoc();
			if ($row === null)
			{
				return false;
			}
			$checkedAt = strtotime($row['checked_at']);
			if ($checkedAt === false ||
				(time() - $checkedAt) > (self::$DNS_CACHE_TTL_DAYS * 86400))
			{
				return false;
			}
			return $row['hostname'];
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return false;
		}
	}

	public function cacheHostname($ipaddress, $hostname)
	{
		try
		{
			$now = date("Y-m-d H:i:s");
			$sql = "SELECT ipaddress FROM #__bfstop_dnscache WHERE ".
				"ipaddress = ".$this->db->quote($ipaddress);
			$this->db->setQuery($sql);
			$exists = $this->db->loadResult();
			$hostnameSql = ($hostname === null) ? 'NULL' : $this->db->quote($hostname);
			if ($exists)
			{
				$query = $this->db->getQuery(true);
				$query->update('#__bfstop_dnscache')
					->set('hostname = '.$hostnameSql)
					->set('checked_at = '.$this->db->quote($now))
					->where('ipaddress = '.$this->db->quote($ipaddress));
				$this->db->setQuery($query);
				$this->db->execute();
			}
			else
			{
				$entry = new \stdClass();
				$entry->ipaddress = $ipaddress;
				$entry->hostname = $hostname;
				$entry->checked_at = $now;
				$this->db->insertObject('#__bfstop_dnscache', $entry);
			}
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}

	private function recordKnownIpUsername($ipaddress, $username)
	{
		try
		{
			$now = date("Y-m-d H:i:s");
			$sql = "SELECT id FROM #__bfstop_knownip WHERE ".
				"ipaddress = ".$this->db->quote($ipaddress).
				" AND LOWER(username) = LOWER(".$this->db->quote($username).")";
			$this->db->setQuery($sql);
			$id = $this->db->loadResult();
			if ($id)
			{
				$query = $this->db->getQuery(true);
				$query->update('#__bfstop_knownip')
					->set('last_success = '.$this->db->quote($now))
					->where('id = '.((int) $id));
				$this->db->setQuery($query);
				$this->db->execute();
			}
			else
			{
				$entry = new \stdClass();
				$entry->ipaddress = $ipaddress;
				$entry->username = $username;
				$entry->first_success = $now;
				$entry->last_success = $now;
				$this->db->insertObject('#__bfstop_knownip', $entry, 'id');
			}
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}

	public function purgeOldEntries($purgeAgeWeeks)
	{
		try
		{
			$this->logger->log("Purging entries older than $purgeAgeWeeks weeks", Log::INFO);
			// all timestamps are written with PHP's date(), so compare against
			// the same clock instead of the database's NOW(), which may use a
			// different time zone
			$now = date("Y-m-d H:i:s");
			$deleteDate = $this->db->quote(self::minutesBefore($now,
				((int) $purgeAgeWeeks) * 7 * 24 * 60));
			$this->db->setQuery('DELETE FROM #__bfstop_failedlogin WHERE logtime < '.$deleteDate);
			$this->db->execute();

			$this->db->setQuery('DELETE FROM #__bfstop_bannedip WHERE duration != 0 AND '.
				$this->addMinutesSql('crdate', 'duration').' < '.$deleteDate);
			$this->db->execute();

			$this->db->setQuery('DELETE FROM #__bfstop_unblock WHERE NOT EXISTS '.
				'(SELECT 1 FROM #__bfstop_bannedip b WHERE b.id = #__bfstop_unblock.block_id)');
			$this->db->execute();

			$this->db->setQuery('DELETE FROM #__bfstop_unblock_token WHERE crdate < '.$deleteDate);
			$this->db->execute();

			// dnscache entries are already treated as expired by
			// getCachedHostname() past DNS_CACHE_TTL_DAYS regardless of the
			// admin-configured purge age above - this just reclaims the
			// storage for rows nothing will ever read as valid again.
			$this->db->setQuery('DELETE FROM #__bfstop_dnscache WHERE checked_at < '.
				$this->db->quote(self::minutesBefore($now, self::$DNS_CACHE_TTL_DAYS * 24 * 60)));
			$this->db->execute();
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}

	/**
	 * Remembers when the periodic maintenance last ran.
	 *
	 * Only this one value is changed in the plugin's stored settings, which
	 * are read from the database right now: writing back the settings the
	 * request was started with would undo whatever an administrator saved in
	 * the meantime.
	 */
	public function saveLastPurge($timestamp)
	{
		try
		{
			$where = function ($query)
			{
				$query->where($this->db->quoteName('type').' = '.$this->db->quote('plugin'))
					->where($this->db->quoteName('folder').' = '.$this->db->quote('system'))
					->where($this->db->quoteName('element').' = '.$this->db->quote('bfstop'));
				return $query;
			};
			$query = $where($this->db->getQuery(true)
				->select($this->db->quoteName('params'))
				->from($this->db->quoteName('#__extensions')));
			$this->db->setQuery($query);
			$params = json_decode((string) $this->db->loadResult(), true);
			if (!is_array($params))
			{
				$params = array();
			}
			$params['lastPurge'] = (int) $timestamp;
			// no table alias here: PostgreSQL doesn't allow qualified column
			// names in the SET clause (issue #206)
			$query = $where($this->db->getQuery(true)
				->update($this->db->quoteName('#__extensions'))
				->set($this->db->quoteName('params').' = '.$this->db->quote(json_encode($params))));
			$this->db->setQuery($query);
			$this->db->execute();
			// the plugin list (with the settings) is cached
			Factory::getContainer()->get(CacheControllerFactoryInterface::class)
				->createCacheController('callback', array('defaultgroup' => 'com_plugins'))
				->clean();
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}

	/**
	 * Deletes the unblock tokens which can't be used any more. A used token is
	 * deleted when it is used, and the unblock page deletes the expired ones
	 * when somebody visits it - but nobody may, and the purge by age only runs
	 * if a purge age is configured.
	 */
	public function purgeExpiredUnblockTokens()
	{
		try
		{
			$this->db->setQuery('DELETE FROM #__bfstop_unblock_token WHERE crdate < '.
				$this->db->quote(date("Y-m-d H:i:s", time() - self::$UNBLOCK_TOKEN_VALID_DAYS * 86400)));
			$this->db->execute();
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}

	/**
	 * Forgets the addresses users logged in from longer ago than $maxAgeDays,
	 * and, oldest first, as many more as needed to keep at most $maxRows.
	 */
	public function pruneKnownIps($maxAgeDays = null, $maxRows = null)
	{
		$maxAgeDays = $maxAgeDays ?? self::$KNOWN_IP_MAX_AGE_DAYS;
		$maxRows = $maxRows ?? self::$KNOWN_IP_MAX_ROWS;
		try
		{
			$this->db->setQuery('DELETE FROM #__bfstop_knownip WHERE last_success < '.
				$this->db->quote(date("Y-m-d H:i:s", time() - $maxAgeDays * 86400)));
			$this->db->execute();
			for ($round = 0; $round < 1000; ++$round)
			{
				$this->db->setQuery('SELECT COUNT(*) FROM #__bfstop_knownip');
				$excess = ((int) $this->db->loadResult()) - $maxRows;
				if ($excess <= 0)
				{
					return;
				}
				$query = $this->db->getQuery(true)
					->select($this->db->quoteName('id'))
					->from($this->db->quoteName('#__bfstop_knownip'))
					->order($this->db->quoteName('last_success').' ASC');
				$this->db->setQuery($query, 0, min($excess, 1000));
				$ids = $this->db->loadColumn();
				if (count($ids) === 0)
				{
					return;
				}
				$this->db->setQuery('DELETE FROM #__bfstop_knownip WHERE id IN ('.
					implode(',', array_map('intval', $ids)).')');
				$this->db->execute();
			}
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}

	/**
	 * Keeps the username statistics below $maxRows by deleting the entries of
	 * the usernames with the fewest attempts, the longest ago first.
	 */
	public function trimUsernameStats($maxRows = null)
	{
		$maxRows = $maxRows ?? self::$USERNAME_STATS_MAX_ROWS;
		try
		{
			for ($round = 0; $round < 1000; ++$round)
			{
				$this->db->setQuery('SELECT COUNT(*) FROM #__bfstop_username_stats');
				$excess = ((int) $this->db->loadResult()) - $maxRows;
				if ($excess <= 0)
				{
					return;
				}
				$query = $this->db->getQuery(true)
					->select($this->db->quoteName('username'))
					->from($this->db->quoteName('#__bfstop_username_stats'))
					->order($this->db->quoteName('attempts').' ASC, '.$this->db->quoteName('last_attempt').' ASC');
				$this->db->setQuery($query, 0, min($excess, 1000));
				$usernames = $this->db->loadColumn();
				if (count($usernames) === 0)
				{
					return;
				}
				$this->db->setQuery('DELETE FROM #__bfstop_username_stats WHERE username IN ('.
					implode(',', array_map(array($this->db, 'quote'), $usernames)).')');
				$this->db->execute();
			}
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}
}
