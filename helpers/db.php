<?php
/*
 * @package Brute Force Stop (bfstop) for Joomla! >=2.5
 * @author Bernhard Froehler
 * @copyright (C) 2012-2014 Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined( '_JEXEC' ) or die;

require_once dirname(__FILE__).'/htaccess.php';

class BFStopDBHelper {

	private $db;
	private $logger;

	// 10 years in minutes. For all intents here sufficiently large to stand for "forever":
	public static $UNLIMITED_DURATION = 5256000;

	function getClientString($id)
	{
		return ($id == 0) ? 'Frontend': 'Backend';
	}

	public function __construct($logger)
	{
		$this->db = JFactory::getDbo();
		$this->logger = $logger;
	}

	public static function checkDBError($db, $logger) {
		$errNum = $db->getErrorNum();
		if ($errNum != 0) {
			$errMsg = $db->getErrorMsg();
			$this->logger->log("Brute Force Stop: Database error (#$errNum) occured: $errMsg", JLog::ERROR);
		}
	}

	public function myCheckDBError()
	{
		BFStopDBHelper::checkDBError($this->db, $this->logger);
	}

	public function eventsInInterval(
		$interval,
		$time,
		$additionalWhere,
		$table='#__bfstop_failedlogin',
		$timecol='logtime')
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
		$this->myCheckDBError();
		return $numberOfEvents;
	}

	public function getNumberOfFailedLogins($interval, $ipaddress, $logtime)
	{
		return $this->eventsInInterval($interval, $logtime,
			'AND ipaddress = '.$this->db->quote($ipaddress).
			' AND handled = 0',
			'#__bfstop_failedlogin',
			'logtime');
	}

	public function getFailedLoginsInLastHour()
	{
		$nowDateTime = date("Y-m-d H:i:s");
		$sql = "SELECT COUNT(*) FROM #__bfstop_failedlogin ".
			"WHERE logtime > DATE_SUB(".
				$this->db->quote($nowDateTime).
			", INTERVAL 1 HOUR)";
		$this->db->setQuery($sql);
		$numRows = $this->db->loadResult();
		$this->myCheckDBError();
		return $numRows;
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
		$sql = "SELECT * FROM #__bfstop_failedlogin t where ipaddress=".
			$this->db->quote($ipAddress).
			" AND t.logtime".
			" between DATE_SUB(".$this->db->quote($curTime).
			", INTERVAL $interval MINUTE) AND ".
			$this->db->quote($curTime);
		$this->db->setQuery($sql);
		$entries = $this->db->loadObjectList();
		$this->myCheckDBError();
		$result = str_pad(JText::_('PLG_SYSTEM_BFSTOP_USERNAME'), 25)." ".
				str_pad(JText::_('PLG_SYSTEM_BFSTOP_IPADDRESS') , 15)." ".
				str_pad(JText::_('PLG_SYSTEM_BFSTOP_DATETIME')  , 20)." ".
				str_pad(JText::_('PLG_SYSTEM_BFSTOP_ORIGIN')	,  8)."\n".
				str_repeat("-", 97)."\n";
		foreach ($entries as $entry)
		{
			$result .= str_pad($entry->username, 25)." ".
				str_pad($entry->ipaddress	  , 15)." ".
				str_pad($entry->logtime		, 20)." ".
				str_pad($this->getClientString($entry->origin),  8)."\n";
		}
		return $result;
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
		$this->db->setQuery($sql);
		$entries = $this->db->loadObjectList();
		foreach($entries as $entry)
		{
			$this->logger->log($action." because of entry: ".
				"id=".$entry->id.", ".
				"ipaddress=".$entry->ipaddress,
				JLog::INFO);
		}
		$this->myCheckDBError();
		return count($entries);
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

	public function isIPWhiteListed($ipaddress)
	{
		$sqlCheckPattern = "SELECT id, ipaddress from #__bfstop_whitelist WHERE %s";
		$sqlIPCheck = sprintf($sqlCheckPattern, $this->ipAddressMatch($ipaddress));
		$sqlSubNetIPv4Check = sprintf($sqlCheckPattern, $this->ipSubNetIPv4Match($ipaddress));
		$entryCount = $this->checkForEntries($sqlIPCheck, "Whitelisted");
		$entryCount += $this->checkForEntries($sqlSubNetIPv4Check, "Whitelisted");
		return ($entryCount > 0);
	}

	public function blockIP($logEntry, $duration, $usehtaccess)
	{
		$blockEntry = new stdClass();
		$blockEntry->ipaddress = $logEntry->ipaddress;
		$blockEntry->crdate = date("Y-m-d H:i:s");
		$blockEntry->duration = $duration;
		if (!$this->db->insertObject('#__bfstop_bannedip', $blockEntry, 'id'))
		{
			$this->logger->log('Insert block entry failed!', JLog::ERROR);
			$blockEntry->id = -1;
		}
		$this->myCheckDBError();
		$this->setFailedLoginHandled($logEntry, false);
		if ($usehtaccess)
		{
			$htaccess = new BFStopHtAccess(JPATH_ROOT, $this->logger);
			$this->logger->log('Blocking '.$logEntry->ipaddress.' through '.$htaccess->getFileName(), JLog::INFO);
			$htaccess->denyIP($logEntry->ipaddress);
		}
		return $blockEntry->id;
	}

	public function getNewUnblockToken($id, $token)
	{
		$tokenEntry = new stdClass();
		$tokenEntry->token = $token;
		$tokenEntry->block_id = $id;
		$tokenEntry->crdate = date("Y-m-d H:i:s");
		if (!$this->db->insertObject('#__bfstop_unblock_token', $tokenEntry))
		{
			// maybe check if duplicate token (=PRIMARY KEY violation) and retry?
			$this->logger->log('Insert unblock token failed!', JLog::ERROR);
			$tokenEntry->token = null;
		}
		$this->myCheckDBError();
		return $tokenEntry->token;
	}

	public function unblockTokenExists($token)
	{
		$sql = "SELECT token FROM #__bfstop_unblock_token WHERE token=".
			$this->db->quote($token);
		$this->db->setQuery($sql);
		$result = $this->db->loadResult();
		$this->myCheckDBError();
		return $result != null;
	}

	private function getUserEmailWhere($where)
	{
		$sql = "select email from #__users where $where LIMIT 1";
		$this->db->setQuery($sql);
		$emailAddress = $this->db->loadResult();
		$this->myCheckDBError();
		return $emailAddress;
	}

	public function getUserEmailByID($uid)
	{
		return $this->getUserEmailWhere("id=".((int)$uid));
	}

	public function getUserEmailByName($username)
	{
		return $this->getUserEmailWhere("username='$username'");
	}

	public function getUserGroupEmail($gid)
	{
		$sql = "SELECT email from #__users u ".
			"LEFT JOIN #__user_usergroup_map g ".
			"ON u.id = g.user_id ".
			"WHERE g.group_id = ".((int)($gid));
		$this->db->setQuery($sql);
		$dbrows = $this->db->loadAssocList();
		$this->myCheckDBError();
		$emailAddresses = array();
		foreach($dbrows as $row)
		{
			$emailAddresses[] = $row['email'];
		}
		return $emailAddresses;
	}

	public function insertFailedLogin($logEntry)
	{
		$logQuery = $this->db->insertObject('#__bfstop_failedlogin', $logEntry, 'id');
		$this->myCheckDBError();
	}

	public function setFailedLoginHandled($info, $restrictOnUsername)
	{
		$sql = 'UPDATE #__bfstop_failedlogin SET handled=1'.
			' WHERE ipaddress='.$this->db->quote($info->ipaddress).
			' AND handled=0';
		if ($restrictOnUsername) {
			$sql .= ' AND username='.$this->db->quote($info->username);
		}
		$this->db->setQuery($sql);
		$this->db->query();
		$this->myCheckDBError();
	}

	public function successfulLogin($info)
	{
		$this->setFailedLoginHandled($info, true);
	}

	public function purgeOldEntries($purgeAgeWeeks)
	{
		$this->logger->log("Purging entries older than $purgeAgeWeeks weeks", JLog::INFO);
		$deleteDate = 'DATE_SUB('.
			' NOW(), INTERVAL '.
			$this->db->quote($purgeAgeWeeks).
			' WEEK)';
		$sql = 'DELETE FROM #__bfstop_failedlogin WHERE logtime < '.$deleteDate;
		$this->db->setQuery($sql);
		$this->db->query();
		$this->myCheckDBError();

		$sql = 'DELETE FROM #__bfstop_bannedip WHERE duration != 0 AND
			DATE_ADD(crdate, INTERVAL duration MINUTE) < '.$deleteDate;
		$this->db->setQuery($sql);
		$this->db->query();
		$this->myCheckDBError();

		$sql = 'DELETE FROM #__bfstop_unblock WHERE NOT EXISTS '.
			'(SELECT 1 FROM #__bfstop_bannedip b WHERE b.id = #__bfstop_unblock.block_id)';
		$this->db->setQuery($sql);
		$this->db->query();
		$this->myCheckDBError();

		$sql = 'DELETE FROM #__bfstop_unblock_token WHERE crdate < '.$deleteDate;
		$this->db->setQuery($sql);
		$this->db->query();
		$this->myCheckDBError();
	}

	public function saveParams($params)
	{
		$query = $this->db->getQuery(true);
		$query->update('#__extensions AS a');
		$query->set('a.params = '. $this->db->quote((string)$params) );
		$query->where('a.element = "bfstop"');
		$this->db->setQuery($query);
		$this->db->query();
	}
}
