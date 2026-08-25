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
		$IPv4NetMask = '~((1 << (32 - SUBSTR(ipaddress, '.$DashPos.'+1, LENGTH(ipaddress)-'.$DashPos.')))-1)';
		$SubNetAddress = 'SUBSTR(ipaddress, 1, LOCATE("/", ipaddress)-1)';
		return
		"(".
			// IPv4 subnet match (CIDR Suffix notation)
			"(".
				"LOCATE('/', ipaddress) != 0 AND LOCATE('.', ipaddress) != 0 AND ".
				"(INET_ATON(".$this->db->quote($ipaddress).") & ".$IPv4NetMask.")".
					" = ".
				"(INET_ATON(".$SubNetAddress.") & ".$IPv4NetMask.")".
			")".
			// IPv6 subnet match -> needs mysql >= 5.6.3 for INET6_ATON
		")";
	}

	private function checkForEntries($sql, $action)
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
			return count($entries);
		}
		catch (\Exception $e)
		{
			$this->logger->log("Database exception occured: ".$e->getMessage(), Log::ERROR);
			return 0;
		}
	}

	public function isIPBlocked($ipaddress)
	{
		$sqlCheckPattern = "SELECT id, ipaddress, crdate, duration FROM #__bfstop_bannedip b WHERE ".
			"%s AND (b.duration=0 OR DATE_ADD(b.crdate, INTERVAL b.duration MINUTE) >= ".
			$this->db->quote(date("Y-m-d H:i:s")).")".
			" AND NOT EXISTS (SELECT 1 FROM #__bfstop_unblock u WHERE b.id = u.block_id)";
		$sqlIPCheck = sprintf($sqlCheckPattern, $this->ipAddressMatch($ipaddress));
		$sqlSubNetIPv4Check = sprintf($sqlCheckPattern, $this->ipSubNetIPv4Match($ipaddress));
		$entryCount = $this->checkForEntries($sqlIPCheck, "Blocked");
		$entryCount += $this->checkForEntries($sqlSubNetIPv4Check, "Blocked");
		return ($entryCount > 0);
	}

	public function isIPOnAllowList($ipaddress)
	{
		$sqlCheckPattern = "SELECT id, ipaddress from #__bfstop_allowlist WHERE %s";
		$sqlIPCheck = sprintf($sqlCheckPattern, $this->ipAddressMatch($ipaddress));
		$sqlSubNetIPv4Check = sprintf($sqlCheckPattern, $this->ipSubNetIPv4Match($ipaddress));
		$entryCount = $this->checkForEntries($sqlIPCheck, "Allowed");
		$entryCount += $this->checkForEntries($sqlSubNetIPv4Check, "Allowed");
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
		$this->db->insertObject('#__bfstop_failedlogin', $logEntry, 'id');
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
	}

	public function purgeOldEntries($purgeAgeWeeks)
	{
		try
		{
			$this->logger->log("Purging entries older than $purgeAgeWeeks weeks", Log::INFO);
			$deleteDate = 'DATE_SUB('.
				' NOW(), INTERVAL '.
				$this->db->quote($purgeAgeWeeks).
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
