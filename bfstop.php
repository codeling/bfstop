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
		$currentSource = $app->getClientId() + 1;
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

	function block($db, $logEntry, $log)
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
			$log->addEntry(array('comment' => 'IP '.$logEntry->ipaddress.' is already blocked!'));
			return;
		}
		$log->addEntry(array('comment' => 'Blocking IP address '.$logEntry->ipaddress));
		// send email notification if not too many notifications already...
		$interval  = $this->params->get('notifyBlockedInterval');
		$maxNumber = $this->params->get('notifyBlockedNumber');
		if ($this->isNotifyEnabled('notifyBlockedSource') &&
			!$this->tooManyRecentEvents($db, $logEntry->logtime, $interval, $maxNumber, '#__banip_entries', 'crdate'))
		{
			$body = $this->getBlockedBody($logEntry);
			$subject = JText::sprintf('BLOCKED_IP_ADDRESS_SUBJECT', $logEntry->ipaddress);
			$this->sendMailNotification($db, $log, $subject, $body);
		}

		$blockEntry = new stdClass();
		$blockEntry->entry = $logEntry->ipaddress;
		$blockEntry->type  = 1;
		$blockEntry->client = 0;
		$db->insertObject('#__banip_entries', $blockEntry);
		$blockEntry->client = 1;
		$db->insertObject('#__banip_entries', $blockEntry);
	}

	function blockIfTooManyAttempts($db, $logEntry, $log)
	{
		if (!$this->plgBanIPEnabled($db))
		{
			$log->addEntry("BanIP plugin is not available!");
		}
		$interval = $this->params->get('blockInterval');
		$maxNumber = $this->params->get('blockNumber');
		if (!$this->moreThanGivenEvents($db, $interval, $maxNumber, $logEntry->logtime,
			" AND ipaddress='".$logEntry->ipaddress."'")) {
			return;
		}
		$this->block($db, $logEntry, $log);
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
	
	function sendMailNotification($db, $log, $subject, $body)
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
	    $log->addEntry(array('comment' => 'Sending out email notification to '.$eid.', subject: '.$subject));
		$mail->Send();
	}

 	public function onUserLoginFailure($user, $options=null)
	{
		JPlugin::loadLanguage('plg_system_bfstop');

		$log =& JLog::getInstance('plg_system_bfstop.log.php');

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
		$interval  = $this->params->get('notifyFailedInterval');
		$maxNumber = $this->params->get('notifyFailedNumber');
		if( $this->isNotifyEnabled('notifyFailedSource') &&
			!$this->tooManyRecentEvents($db, $logEntry->logtime, $interval, $maxNumber))
		{
			$body = $this->getFailedLoginBody($logEntry);
			$subject = JText::_sprintf("FAILED_LOGIN_ATTEMPT", .JURI::root());
			$this->sendMailNotification($db, $log, $subject, $body);
		}
		$this->blockIfTooManyAttempts($db, $logEntry, $log);
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

