<?php
defined('_JEXEC') or die;
/*
Brute Force Stop (bfstop) Joomla Plugin
Copyright (C) 2012 Bernhard Froehler

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

jimport('joomla.event.plugin');
jimport('joomla.error.log');

class plgSystembfstop extends JPlugin
{

	// default interval used for notifications is one day:
	private static $ONE_DAY=24;
	private $log;

	function plgSystembfstop(& $subject, $config) 
	{
		parent::__construct($subject, $config);
	}

	function moreThanGivenEvents($db, $interval, $maxNumber, $logtime,
		$additionalWhere = '',
		$table='#__bfstop_failedlogin',
		$timecol='logtime')
	{
		// check if in the last $interval hours, $number incidents have occured already:
		$sql = "SELECT COUNT(*) FROM ".$table." ".
				"WHERE ".$timecol." between DATE_SUB('$logtime', INTERVAL $interval HOUR) AND '$logtime'".
				$additionalWhere;
		$db->setQuery($sql);
		$recentEvents = ((int)$db->loadResult());
		$this->log->addEntry(array('comment' => "moreThanGivenEvents(interval=$interval, maxNumber=$maxNumber, logtime=$logtime, additionalWhere=$additionalWhere, table=$table, timecol=$timecol)\n    sql: $sql; recentEvents: $recentEvents"));
		return $recentEvents > $maxNumber;
	}

	function tooManyRecentEvents($db, $logtime, $interval, $maxNumber,
		$table='#__bfstop_failedlogin',
		$timecol='logtime')
	{
		return $this->moreThanGivenEvents($db, $interval, $maxNumber, $logtime, '', $table, $timecol);
	}

	function isNotifyEnabled($notifyOption)
	{
		$notifySources = $this->params->get($notifyOption);
		$app =& JFactory::getApplication();
		$currentSource = $app->getClientId() + 1;
		$this->log->addEntry(array('comment' => "isNotifyEnabled(notifyOption=$notifyOption)\n    currentSource: $currentSource; notifySources: $notifySources; result: ".
			(( ($notifySources & $currentSource) == $currentSource )? 'true': 'false')));
		return ( ($notifySources & $currentSource) == $currentSource );
	}

	function plgBanIPEnabled($db)
	{
		$sql = "select COUNT(*) from `#__extensions` where name='plg_system_banip'";
		$db->setQuery($sql);
		return ($db->loadResult() > 0);
	}

	function getBlockedBody($logEntry)
	{
		return JText::sprintf('BLOCKED_IP_ADDRESS_BODY', $logEntry->ipaddress,
				$this->getFailedLoginBody($logEntry));
	}

	function block($db, $logEntry)
	{
		$blockEnabled  = (bool)$this->params->get('blockEnabled');
		if (!$blockEnabled) {
			return;
		}
		// if the IP address is blocked we actually shouldn't be here in the first place
		// I guess, but just to make sure
		$sqlCheck = "select COUNT(*) from #__banip_entries where entry='$logEntry->ipaddress'";
		$db->setQuery($sqlCheck);
		$numRows = $db->loadResult();
		if ($numRows > 0)
		{
			$this->log->addEntry(array('comment' => 'IP '.$logEntry->ipaddress.' is already blocked!'));
			return;
		}
		$this->log->addEntry(array('comment' => 'Blocking IP address '.$logEntry->ipaddress));
		// send email notification if not too many notifications already...
		$interval  = self::$ONE_DAY;
		$maxNumber = $this->params->get('notifyBlockedNumber');
		if ($this->isNotifyEnabled('notifyBlockedSource') &&
			!$this->tooManyRecentEvents($db, $logEntry->logtime, $interval, $maxNumber, '#__banip_entries', 'crdate'))
		{
			$body = $this->getBlockedBody($logEntry);
			$subject = JText::sprintf('BLOCKED_IP_ADDRESS_SUBJECT', $logEntry->ipaddress);
			$this->sendMailNotification($db, $subject, $body);
		}

		$blockEntry = new stdClass();
		$blockEntry->entry = $logEntry->ipaddress;
		$blockEntry->type  = 1;
		$blockEntry->client = 0;
		$db->insertObject('#__banip_entries', $blockEntry);
		$blockEntry->client = 1;
		$db->insertObject('#__banip_entries', $blockEntry);
	}

	function blockIfTooManyAttempts($db, $logEntry)
	{
		if (!$this->plgBanIPEnabled($db))
		{
			$this->log->addEntry("BanIP plugin is not available!");
		}
		$interval = $this->params->get('blockInterval');
		$maxNumber = $this->params->get('blockNumber');
		if (!$this->moreThanGivenEvents($db, $interval, $maxNumber, $logEntry->logtime,
			" AND ipaddress='".$logEntry->ipaddress."'")) {
			return;
		}
		$this->block($db, $logEntry);
	}

	function getFailedLoginBody($logEntry)
	{
		$bodys = JText::sprintf('FAILED_LOGIN_ATTEMPT', JURI::root()) ."\n";
		$bodys.= JText::_('USERNAME')  . " :\t". $logEntry->username  ."\n";
		$bodys.= JText::_('PASSWORD')  . " :\t". $logEntry->password  ."\n";
		$bodys.= JText::_('IPADDRESS') . " :\t". $logEntry->ipaddress ."\n";
		$bodys.= JText::_('ERROR')     . " :\t". $logEntry->error     ."\n";
		$bodys.= JText::_('DATETIME')  . " :\t". $logEntry->logtime   ."\n";
		$bodys.= JText::_('ORIGIN')    . " :\t". $logEntry->origin    ."\n";
		return $bodys;
	}
	
	function sendMailNotification($db, $subject, $body)
	{
		if($this->params->get( 'emailtype' ) ==1)
		{
			$eid = $this->params->get('emailaddress');
		}
		if($this->params->get( 'emailtype' ) ==0)
		{
			$uid = $this->params->get('userIDs');
			$sql = "select email from #__users where id='$uid'";
			$db->setQuery($sql);
			$eid = $db->loadResult();
		}
		$response->error_message = '';
		$mail =& JFactory::getMailer();
		$mail->setSubject($subject);
		$mail->setBody($body);
		$mail->addRecipient($eid);
		$this->log->addEntry(array('comment' => 'Sending out email notification to '.$eid.', subject: '.$subject));
		$sendSuccess = $mail->Send();
		$this->log->addEntry(array('comment' => 'Sending was '.(($sendSuccess)?'successful':'not successful: '.json_encode($mail->ErrorInfo))));
	}

 	public function onUserLoginFailure($user, $options=null)
	{
		JPlugin::loadLanguage('plg_system_bfstop');

		$this->log =& JLog::getInstance('plg_system_bfstop.log.php');

		$delayDuration = (int)$this->params->get('delayDuration');
		if ($delayDuration != 0)
		{
			sleep($delayDuration);
		}
		$db = JFactory::getDbo();
		$app =& JFactory::getApplication();

		$logEntry = new stdClass();
		$logEntry->id        = null;
		$logEntry->ipaddress = getenv('REMOTE_ADDR');
		$logEntry->logtime   = date("Y-m-d H:i:s");
		$logEntry->error     = $user['error_message'];
		$logEntry->username  = $user['username'];
		$logEntry->password  = $user['password'];
		$logEntry->origin    = ($app->getClientId() == 0) ? 'Frontend': 'Backend';

		$this->createTable($db);
	
		// insert into log:
		$logQuery = $db->insertObject('#__bfstop_failedlogin', $logEntry, 'id');

		// client ID's: 0-frontend, 1-backend
		// for our purpose (bitmask), we need 1-frontend 2-backend
		$interval  = self::$ONE_DAY;
		$maxNumber = $this->params->get('notifyFailedNumber');
		if( $this->isNotifyEnabled('notifyFailedSource') &&
			!$this->tooManyRecentEvents($db, $logEntry->logtime, $interval, $maxNumber))
		{
			$body = $this->getFailedLoginBody($logEntry);
			$subject = JText::sprintf("FAILED_LOGIN_ATTEMPT", JURI::root());
			$this->sendMailNotification($db, $subject, $body);
		}
		$this->blockIfTooManyAttempts($db, $logEntry);
		return true;
	}

	function createTable($db)
	{
		// TODO: move that to install!
		$createTableQuery = 'CREATE TABLE IF NOT EXISTS #__bfstop_failedlogin('
			.'id int(10) NOT NULL auto_increment,'
			.'username varchar(25) NOT NULL,'
			.'password varchar(25) NOT NULL,'
			.'ipaddress varchar(35) NOT NULL,'
			.'error varchar(55) NOT NULL,'
			.'logtime datetime NOT NULL,'
			.'origin int NOT NULL,'
			.'PRIMARY KEY  (id)'
			.')';
		$db->setQuery( $createTableQuery );
		$db->query();
	}

}

