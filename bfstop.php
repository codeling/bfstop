<?php
/*
 * @package Brute Force Stop (bfstop) for Joomla! >=2.5
 * @author Bernhard Froehler
 * @copyright (C) 2012 Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

jimport('joomla.event.plugin');
jimport('joomla.error.log');

class plgSystembfstop extends JPlugin
{

	// default interval used for notifications is one day:
	private static $ONE_DAY=24;
	private $log;
	private $db;
	private $app;

	function log($msg)
	{
		$this->log->addEntry(array('comment' => $msg));
	}

	function plgSystembfstop(& $subject, $config) 
	{
		parent::__construct($subject, $config);
	}

	function checkDBError()
	{
		$errNum = $this->db->getErrorNum();
		if ($errNum != 0)
		{
			$errMsg = $this->db->getErrorMsg();
			$this->log("Database error (#$errNum) occured: $errMsg");
		}
	}

	function moreThanGivenEvents($interval, $maxNumber, $logtime,
		$additionalWhere = '',
		$table='#__bfstop_failedlogin',
		$timecol='logtime')
	{
		// check if in the last $interval hours, $number incidents have occured already:
		$sql = "SELECT COUNT(*) FROM ".$table." ".
				"WHERE ".$timecol." between DATE_SUB('$logtime', INTERVAL $interval HOUR) AND '$logtime'".
				$additionalWhere;
		$this->db->setQuery($sql);
		$recentEvents = ((int)$this->db->loadResult());
		$this->checkDBError();
//		$this->log("moreThanGivenEvents(interval=$interval, maxNumber=$maxNumber, logtime=$logtime, additionalWhere=$additionalWhere, table=$table, timecol=$timecol)\n    sql: $sql; recentEvents: $recentEvents");
		return $recentEvents > $maxNumber;
	}

	function isNotificationAllowed($logtime, $interval, $maxNumber,
		$table='#__bfstop_failedlogin',
		$timecol='logtime')
	{
		// -1 stands for an unlimited number of notifications
		if ($maxNumber == -1)
		{
			return true;
		}
		// 0 stands for no notifications
		else if ($maxNumber == 0)
		{
			return false;
		}
		return !$this->moreThanGivenEvents($interval, $maxNumber, $logtime, '', $table, $timecol);
	}

	function getFormattedFailedList($ipAddress, $curTime, $interval)
	{
		$sql = "SELECT * FROM #__bfstop_failedlogin where ipaddress='$ipAddress'".
			" AND logtime between DATE_SUB('$curTime', INTERVAL $interval HOUR) AND '$curTime'";
		$this->db->setQuery($sql);
		$entries = $this->db->loadObjectList();
		$this->checkDBError();
		$result = str_pad(JText::_('USERNAME'), 25)." ".
				str_pad(JText::_('PASSWORD')  , 25)." ".
				str_pad(JText::_('IPADDRESS') , 15)." ".
				str_pad(JText::_('DATETIME')  , 20)." ".
				str_pad(JText::_('ORIGIN')    ,  8)."\n".
				str_repeat("-", 97)."\n";
		foreach ($entries as $entry)
		{
			$result .= str_pad($entry->username               , 25)." ".
				str_pad($entry->password                      , 25)." ".
				str_pad($entry->ipaddress                     , 15)." ".
				str_pad($entry->logtime                       , 20)." ".
				str_pad($this->getClientString($entry->origin),  8)."\n";
		}
		return $result;
	}

	function getBlockedBody($logEntry, $interval)
	{
		return JText::sprintf('BLOCKED_IP_ADDRESS_BODY',
			$logEntry->ipaddress,
			$this->getFormattedFailedList($logEntry->ipaddress,
				$logEntry->logtime,
				$interval
			)
		);
	}

	function isIPBlocked($ipaddress)
	{
		$sqlCheck = "SELECT COUNT(*) from #__bfstop_bannedip where ipaddress='$ipaddress'";
		$this->db->setQuery($sqlCheck);
		$numRows = $this->db->loadResult();
		$this->checkDBError();
		return ($numRows > 0);
	}

	function block($logEntry, $blockInterval)
	{
		$blockEnabled  = (bool)$this->params->get('blockEnabled');
		if (!$blockEnabled) {
			return;
		}
		// if the IP address is blocked we actually shouldn't be here in the first place
		// I guess, but just to make sure
		if ($this->isIPBlocked($logEntry->ipaddress))
		{
			$this->log('IP '.$logEntry->ipaddress.' is already blocked!');
			return;
		}
		$blockEntry = new stdClass();
		$blockEntry->ipaddress = $logEntry->ipaddress;
		$blockEntry->crdate = date("Y-m-d H:i:s");
		$this->db->insertObject('#__bfstop_bannedip', $blockEntry);
		$this->checkDBError();

		$this->log('Blocked IP address '.$logEntry->ipaddress);
		// send email notification if not too many notifications already...
		$interval  = self::$ONE_DAY;
		$maxNumber = $this->params->get('notifyBlockedNumber');
		if ($this->isNotificationAllowed(
			$logEntry->logtime, $interval, $maxNumber,
			'#__bfstop_bannedip', 'crdate'))
		{
			$body = $this->getBlockedBody($logEntry, $blockInterval);
			$subject = JText::sprintf('BLOCKED_IP_ADDRESS_SUBJECT', $logEntry->ipaddress);
			$this->sendMailNotification($subject, $body);
		}
	}

	function blockIfTooManyAttempts($logEntry)
	{
		$interval = $this->params->get('blockInterval');
		$maxNumber = $this->params->get('blockNumber');
		// -1 to block for the blockNumber'th time already
		if (!$this->moreThanGivenEvents($interval, $maxNumber-1, $logEntry->logtime,
			" AND ipaddress='".$logEntry->ipaddress."'")) {
			return;
		}
		$this->block($logEntry, $interval);
	}

	function getFailedLoginBody($logEntry)
	{
		$bodys = JText::sprintf('FAILED_LOGIN_ATTEMPT', JURI::root()) ."\n";
		$bodys.= str_pad(JText::_('USERNAME').":",15)  . $logEntry->username  ."\n";
		$bodys.= str_pad(JText::_('PASSWORD').":",15)  . $logEntry->password  ."\n";
		$bodys.= str_pad(JText::_('IPADDRESS').":",15) . $logEntry->ipaddress ."\n";
		$bodys.= str_pad(JText::_('ERROR').":",15)     . $logEntry->error     ."\n";
		$bodys.= str_pad(JText::_('DATETIME').":",15)  . $logEntry->logtime   ."\n";
		$bodys.= str_pad(JText::_('ORIGIN').":",15)    . $this->getClientString($logEntry->origin)."\n";
		return $bodys;
	}
	
	function sendMailNotification($subject, $body)
	{
		if($this->params->get( 'emailtype' ) == 0)
		{
			$uid = $this->params->get('userIDs');
			$sql = "select email from #__users where id='$uid'";
			$this->db->setQuery($sql);
			$emailAddress = $this->db->loadResult();
			$this->checkDBError();
		}
		else if($this->params->get( 'emailtype' ) == 1)
		{
			$emailAddress = $this->params->get('emailaddress');
		}
		else
		{
			$this->log('Invalid source for retrieval of email address!');
			return;
		}
		if (!isset($emailAddress) || strcmp($emailAddress, '') == 0)
		{
			$this->log('No user selected or no email address specified!');
			return;
		}
		$response->error_message = '';
		$mail =& JFactory::getMailer();
		$mail->setSubject($subject);
		$mail->setBody($body);
		$mail->addRecipient($emailAddress);
		$sendSuccess = $mail->Send();
		$this->log('Sent email to '.$emailAddress.', subject: '.$subject.'; '.
			(($sendSuccess)?'successful':'not successful: '.json_encode($mail->ErrorInfo)));
	}

	function getClientString($id)
	{
		return ($id == 0) ? 'Frontend': 'Backend';
	}

	function getIPAddr()
	{
		return getenv('REMOTE_ADDR');
	}
	
	private function init()
	{
		$this->log =& JLog::getInstance('plg_system_bfstop.log.php');
		$this->db  =& JFactory::getDbo();
		$this->app =& JFactory::getApplication();
	}

 	public function onUserLoginFailure($user, $options=null)
	{
		$this->init();
		JPlugin::loadLanguage('plg_system_bfstop');
		$delayDuration = (int)$this->params->get('delayDuration');
		if ($delayDuration != 0)
		{
			sleep($delayDuration);
		}

		$logEntry = new stdClass();
		$logEntry->id        = null;
		$logEntry->ipaddress = $this->getIPAddr();
		$logEntry->logtime   = date("Y-m-d H:i:s");
		$logEntry->error     = $user['error_message'];
		$logEntry->username  = $user['username'];
		$logEntry->password  = $user['password'];
		$logEntry->origin    = $this->app->getClientId();
	
		// insert into log:
		$logQuery = $this->db->insertObject('#__bfstop_failedlogin', $logEntry, 'id');
		$this->checkDBError();

		// client ID's: 0-frontend, 1-backend
		// for our purpose (bitmask), we need 1-frontend 2-backend
		$interval  = self::$ONE_DAY;
		$maxNumber = $this->params->get('notifyFailedNumber');
		if( $this->isNotificationAllowed($logEntry->logtime, $interval, $maxNumber))
		{
			$body = $this->getFailedLoginBody($logEntry);
			$subject = JText::sprintf("FAILED_LOGIN_ATTEMPT", JURI::root());
			$this->sendMailNotification($subject, $body);
		}
		$this->blockIfTooManyAttempts($logEntry);
		return true;
	}

	public function onAfterInitialise()
	{
		$this->init();
		$ipaddress = $this->getIPAddr();
//		$this->log("onAfterInitialise; ipAddress: $ipaddress");
		if ($this->isIPBlocked($ipaddress))
		{
			$this->log("Blocked IP Address $ipaddress tried to access ".
				$this->getClientString($this->app->getClientId()) );
			JPlugin::loadLanguage('plg_system_bfstop');
			$message = $this->params->get('blockedMessage', JText::_('BLOCKED_IP_MESSAGE'));
			echo $message;
			$this->app =& JFactory::getApplication();
			$this->app->close();
			return false;
		}
		return true;
	}

}

