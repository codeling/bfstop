<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;

class DatabaseHelper
{
	private $db;
	private $logger;

	// 10 years in minutes. For all intents here sufficiently large to stand for "forever":
	public static $UNLIMITED_DURATION = 5256000;

	// how long a reverse-DNS lookup result is trusted before being redone -
	// keeps the (potentially slow) gethostbyaddr() call to at most once per
	// IP per TTL window, see issue #103
	public static $DNS_CACHE_TTL_DAYS = 7;

	public function getClientString($id)
	{
		return ($id == 0) ? 'Frontend' : 'Backend';
	}

	public function __construct(LoggerHelper $logger)
	{
		$this->db = Factory::getDbo();
		$this->logger = $logger;
	}

	public function myCheckDBError()
	{
		$errNum = $this->db->getErrorNum();
		if ($errNum != 0)
		{
			$this->logger->log("Database error (#$errNum) occured: ".$this->db->getErrorMsg(), Log::ERROR);
		}
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
				" between DATE_SUB(".
				$this->db->quote($time).
				", INTERVAL $interval MINUTE) AND ".
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
				"WHERE logtime > DATE_SUB(".
					$this->db->quote($nowDateTime).
					", INTERVAL 1 HOUR)";
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
				" between DATE_SUB(".$this->db->quote($curTime).
				", INTERVAL $interval MINUTE) AND ".
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
				$result .= str_pad($entry->username, 25)." ".
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

	public function ipAddressMatch($ipaddress)
	{
		// literal match
		return
		"(".
			"ipaddress=".$this->db->quote($ipaddress)." AND ".
			"LOCATE('/', ipaddress) = 0".
		")";
	}

	public function ipSubNetIPv4Match($ipaddress)
	{
		$DashPos = 'LOCATE("/", ipaddress)';
		$SubNetAddress = 'SUBSTR(ipaddress, 1, LOCATE("/", ipaddress)-1)';
		$BitsText = 'SUBSTR(ipaddress, '.$DashPos.'+1, LENGTH(ipaddress)-'.$DashPos.')';
		// the original mask expression used $BitsText directly as a
		// string in "32 - SUBSTR(...)"; MySQL/MariaDB then coerces that
		// implicitly to a DOUBLE, and if a stored row has a corrupted
		// prefix length (huge or malformed - e.g. hand-edited in the DB,
		// or an old bug that let one in), "32 - <huge>" produces a DOUBLE
		// whose magnitude overflows BIGINT UNSIGNED once the shift
		// operator converts it, raising "BIGINT UNSIGNED value is out of
		// range" for every query against the whole table (#134).
		$RawBits = 'CAST('.$BitsText.' AS SIGNED)';
		// clamped to [0,32] before any further arithmetic, so a corrupted
		// row can never blow up the mask math into an out-of-range error -
		// same fix as ipSubNetIPv6Match() below (#142). The BitsValid
		// guard further down keeps such a clamped-but-bogus row from
		// silently matching as a wildcard.
		$Bits = 'GREATEST(LEAST('.$RawBits.', 32), 0)';
		$IPv4NetMask = '~((1 << (32 - '.$Bits.'))-1)';
		// rejects a corrupted prefix length outright (rather than letting
		// the clamp above silently turn it into a "/0" wildcard match) -
		// the digit-count-limited REGEXP is itself overflow-safe, so this
		// check never needs the clamped value to decide validity
		$BitsValid = $BitsText." REGEXP '^[0-9]{1,2}$' AND ".$RawBits." BETWEEN 0 AND 32";
		return
		"(".
			// IPv4 subnet match (CIDR Suffix notation)
			"(".
				"LOCATE('/', ipaddress) != 0 AND LOCATE('.', ipaddress) != 0 AND ".
				$BitsValid." AND ".
				"(INET_ATON(".$this->db->quote($ipaddress).") & ".$IPv4NetMask.")".
					" = ".
				"(INET_ATON(".$SubNetAddress.") & ".$IPv4NetMask.")".
			")".
		")";
	}

	// splits a stored INET6_ATON() value into its high/low 8-byte halves and
	// widens each to a plain BIGINT UNSIGNED, since MySQL's bitwise operators
	// only work on 64-bit integers, not on 16-byte VARBINARY values directly
	// (see issue #142/#117 - a 128-bit mask can't be applied in one step)
	private function inet6HalfAsUnsigned($ipExpr, $startByte)
	{
		return 'CAST(CONV(HEX(SUBSTR(INET6_ATON('.$ipExpr.'), '.$startByte.', 8)), 16, 10) AS UNSIGNED)';
	}

	public function ipSubNetIPv6Match($ipaddress)
	{
		$ipQuoted = $this->db->quote($ipaddress);
		$DashPos = 'LOCATE("/", ipaddress)';
		$SubNetAddress = 'SUBSTR(ipaddress, 1, '.$DashPos.'-1)';
		$BitsText = 'SUBSTR(ipaddress, '.$DashPos.'+1, LENGTH(ipaddress)-'.$DashPos.')';
		// signed, not unsigned: bits-64 goes negative for a /0..'/63 prefix,
		// and an UNSIGNED subtraction underflowing below 0 raises "BIGINT
		// UNSIGNED out of range" in strict mode (this is the #117 crash).
		$RawBits = 'CAST('.$BitsText.' AS SIGNED)';
		// clamped to [0,128] before any further arithmetic, so a row with a
		// corrupted prefix length (e.g. hand-edited in the DB) can never
		// blow up the '-64'/shift math below into an out-of-range error -
		// see #134, which hit this exact class of bug in the analogous
		// IPv4 query. The BitsValid guard further down keeps such a
		// clamped-but-bogus row from silently matching as a wildcard.
		$Bits = 'GREATEST(LEAST('.$RawBits.', 128), 0)';

		// the 128-bit prefix length is applied as two independent 64-bit
		// masks, one per half of the address
		$HiBits = 'LEAST('.$Bits.', 64)';
		$LoBits = 'GREATEST('.$Bits.' - 64, 0)';
		$HiMask = '(0xFFFFFFFFFFFFFFFF << (64 - '.$HiBits.'))';
		$LoMask = '(0xFFFFFFFFFFFFFFFF << (64 - '.$LoBits.'))';

		// rejects a corrupted prefix length outright (rather than letting
		// the clamp above silently turn it into a "/0" wildcard match) -
		// the digit-count-limited REGEXP is itself overflow-safe, so this
		// check never needs the clamped value to decide validity
		$BitsValid = $BitsText." REGEXP '^[0-9]{1,3}$' AND ".$RawBits." BETWEEN 0 AND 128";

		return
		"(".
			// IPv6 subnet match (CIDR Suffix notation)
			"(".
				"LOCATE('/', ipaddress) != 0 AND LOCATE(':', ipaddress) != 0 AND ".
				$BitsValid." AND ".
				"INET6_ATON(".$ipQuoted.") IS NOT NULL AND LENGTH(INET6_ATON(".$ipQuoted.")) = 16 AND ".
				"INET6_ATON(".$SubNetAddress.") IS NOT NULL AND LENGTH(INET6_ATON(".$SubNetAddress.")) = 16 AND ".
				"(".$this->inet6HalfAsUnsigned($ipQuoted, 1)." & ".$HiMask.")".
					" = ".
				"(".$this->inet6HalfAsUnsigned($SubNetAddress, 1)." & ".$HiMask.")".
					" AND ".
				"(".$this->inet6HalfAsUnsigned($ipQuoted, 9)." & ".$LoMask.")".
					" = ".
				"(".$this->inet6HalfAsUnsigned($SubNetAddress, 9)." & ".$LoMask.")".
			")".
		")";
	}

	private function loadMatchingEntries($sql, $action)
	{
		try
		{
			$this->db->setQuery($sql);
			$entries = $this->db->loadObjectList();
			foreach ($entries as $entry)
			{
				$this->logger->log($action." because of entry: ".
					"id=".$entry->id.", ".
					"ipaddress=".$entry->ipaddress,
					Log::DEBUG);
			}
			return $entries;
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return array();
		}
	}

	private function checkForEntries($sql, $action)
	{
		return count($this->loadMatchingEntries($sql, $action));
	}

	/**
	 * IDs of all currently active blocks matching the given IP address,
	 * whether as single address or as part of a blocked IPv4/IPv6 subnet.
	 */
	public function getActiveBlockIds($ipaddress)
	{
		$sqlCheckPattern = "SELECT id, ipaddress, crdate, duration FROM #__bfstop_bannedip b WHERE ".
			"%s AND (b.duration=0 OR DATE_ADD(b.crdate, INTERVAL b.duration MINUTE) >= ".
			$this->db->quote(date("Y-m-d H:i:s")).")".
			" AND NOT EXISTS (SELECT 1 FROM #__bfstop_unblock u WHERE b.id = u.block_id)";
		$ids = array();
		foreach (array(
				$this->ipAddressMatch($ipaddress),
				$this->ipSubNetIPv4Match($ipaddress),
				$this->ipSubNetIPv6Match($ipaddress)) as $matchExpr)
		{
			foreach ($this->loadMatchingEntries(sprintf($sqlCheckPattern, $matchExpr), "Blocked") as $entry)
			{
				$ids[] = (int)$entry->id;
			}
		}
		return array_values(array_unique($ids));
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
		$sqlCheckPattern = "SELECT id, ipaddress from #__bfstop_allowlist WHERE %s";
		$sqlIPCheck = sprintf($sqlCheckPattern, $this->ipAddressMatch($ipaddress));
		$sqlSubNetIPv4Check = sprintf($sqlCheckPattern, $this->ipSubNetIPv4Match($ipaddress));
		$sqlSubNetIPv6Check = sprintf($sqlCheckPattern, $this->ipSubNetIPv6Match($ipaddress));
		$entryCount = $this->checkForEntries($sqlIPCheck, "Allowed");
		$entryCount += $this->checkForEntries($sqlSubNetIPv4Check, "Allowed");
		$entryCount += $this->checkForEntries($sqlSubNetIPv6Check, "Allowed");
		return ($entryCount > 0);
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
				$blockEntry->id = -1;
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

	public function getNewUnblockToken($id, $token)
	{
		try
		{
			$tokenEntry = new \stdClass();
			$tokenEntry->token = $token;
			$tokenEntry->block_id = $id;
			$tokenEntry->crdate = date("Y-m-d H:i:s");
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
				$this->db->quote($username).', 1, '.$time.', '.$time.')'.
				' ON DUPLICATE KEY UPDATE attempts=attempts+1, last_attempt='.$time;
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

	public function successfulLogin($info)
	{
		$this->setFailedLoginHandled($info, true);
		$this->recordKnownIpUsername($info->ipaddress, $info->username);
	}

	public function isKnownIpUsername($ipaddress, $username)
	{
		try
		{
			$sql = "SELECT COUNT(*) FROM #__bfstop_knownip WHERE ".
				"ipaddress = ".$this->db->quote($ipaddress).
				" AND username = ".$this->db->quote($username);
			$this->db->setQuery($sql);
			return ((int) $this->db->loadResult()) > 0;
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
				" AND username = ".$this->db->quote($username);
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
			$now = $this->db->quote(date("Y-m-d H:i:s"));
			$deleteDate = 'DATE_SUB('.$now.
				', INTERVAL '.((int) $purgeAgeWeeks).
				' WEEK)';
			$this->db->setQuery('DELETE FROM #__bfstop_failedlogin WHERE logtime < '.$deleteDate);
			$this->db->execute();

			$this->db->setQuery('DELETE FROM #__bfstop_bannedip WHERE duration != 0 AND
				DATE_ADD(crdate, INTERVAL duration MINUTE) < '.$deleteDate);
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
				'DATE_SUB('.$now.', INTERVAL '.self::$DNS_CACHE_TTL_DAYS.' DAY)');
			$this->db->execute();
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}

	public function saveParams($params)
	{
		try
		{
			$query = $this->db->getQuery(true);
			$query->update('#__extensions AS a');
			$query->set('a.params = '. $this->db->quote((string)$params));
			$query->where('a.element = '.$this->db->quote('bfstop'));
			$this->db->setQuery($query);
			$this->db->execute();
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
		}
	}
}
