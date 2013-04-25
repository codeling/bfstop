<?php
class BFStopDBHelper {

	public static function getInstance() {
		return new BFStopDBHelper();
	}

	private $db;

	function getClientString($id)
	{
		return ($id == 0) ? 'Frontend': 'Backend';
	}

	public function __construct()
	{
		$this->db = JFactory::getDbo();
	}

	public function checkDBError()
	{
		$errNum = $this->db->getErrorNum();
		if ($errNum != 0)
		{
			$errMsg = $this->db->getErrorMsg();
			$this->log("Database error (#$errNum) occured: $errMsg", JLog::EMERGENCY);
		}
	}

	public function moreThanGivenEvents($interval, $maxNumber, $logtime,
		$additionalWhere = '',
		$table='#__bfstop_failedlogin',
		$timecol='logtime')
	{
		// check if in the last $interval hours, $number incidents have occured already:
		$sql = "SELECT COUNT(*) FROM ".$table." t ".
				"WHERE t.".$timecol." between DATE_SUB('$logtime', INTERVAL $interval MINUTE) AND '$logtime'".
				$additionalWhere;
		$this->db->setQuery($sql);
		$recentEvents = ((int)$this->db->loadResult());
		$this->checkDBError();
		return $recentEvents > $maxNumber;
	}

	public function getNumberOfFailedLogins($interval, $ipaddress, $logtime)
	{
		$sql = "SELECT COUNT(*) FROM #__bfstop_failedlogin t ".
			"WHERE logtime between DATE_SUB('$logtime', INTERVAL $interval MINUTE) AND '$logtime' ".
			"AND ipaddress = '".$ipaddress."' ".
			"AND NOT exists (SELECT 1 FROM #__bfstop_lastlogin u".
			" WHERE u.username = t.username ".
			"     AND u.ipaddress = t.ipaddress ".
			"     AND u.logtime > t.logtime)";
		$this->db->setQuery($sql);
		$number = ((int)$this->db->loadResult());
		$this->checkDBError();
		return $number;
	}

	public function getFormattedFailedList($ipAddress, $curTime, $interval)
	{
		$sql = "SELECT * FROM #__bfstop_failedlogin where ipaddress='$ipAddress'".
			" AND logtime between DATE_SUB('$curTime', INTERVAL $interval MINUTE) AND '$curTime'";
		$this->db->setQuery($sql);
		$entries = $this->db->loadObjectList();
		$this->checkDBError();
		$result = str_pad(JText::_('USERNAME'), 25)." ".
				str_pad(JText::_('IPADDRESS') , 15)." ".
				str_pad(JText::_('DATETIME')  , 20)." ".
				str_pad(JText::_('ORIGIN')    ,  8)."\n".
				str_repeat("-", 97)."\n";
		foreach ($entries as $entry)
		{
			$result .= str_pad($entry->username               , 25)." ".
				str_pad($entry->ipaddress                     , 15)." ".
				str_pad($entry->logtime                       , 20)." ".
				str_pad($this->getClientString($entry->origin),  8)."\n";
		}
		return $result;
	}

	public function isIPBlocked($ipaddress, $blockDuration)
	{
		$sqlCheck = "SELECT COUNT(*) from #__bfstop_bannedip WHERE ipaddress='$ipaddress'";
		if ($blockDuration != 0)
		{
			$sqlCheck .= " and DATE_ADD(crdate, INTERVAL $blockDuration MINUTE) >= NOW()";
		}
		$this->db->setQuery($sqlCheck);
		$numRows = $this->db->loadResult();
		$this->checkDBError();
		return ($numRows > 0);
	}

	public function blockIP($logEntry)
	{
		$blockEntry = new stdClass();
		$blockEntry->ipaddress = $logEntry->ipaddress;
		$blockEntry->crdate = date("Y-m-d H:i:s");
		$this->db->insertObject('#__bfstop_bannedip', $blockEntry);
		$this->checkDBError();
	}

	public function getEmailAddress($uid)
	{
		$sql = "select email from #__users where id='$uid'";
		$this->db->setQuery($sql);
		$emailAddress = $this->db->loadResult();
		$this->checkDBError();
	}

	public function insertFailedLogin($logEntry)
	{
		$logQuery = $this->db->insertObject('#__bfstop_failedlogin', $logEntry, 'id');
		$this->checkDBError();
	}

	public function insertSuccessLogin($logEntry)
	{
		$deleteQuery = $this->db->getQuery(true);
		$conditions = array(
			"username='".$logEntry->username."'");
		$deleteQuery->delete($this->db->quoteName('#__bfstop_lastlogin'));
		$deleteQuery->where($conditions);
		$this->db->setQuery($deleteQuery);
		$this->db->query();
		$this->checkDBError();
		$logQuery = $this->db->insertObject('#__bfstop_lastlogin', $logEntry, 'username');
		$this->checkDBError();
	}

}
