<?php
/*
 * @package Brute Force Stop (bfstop) for Joomla! >=2.5
 * @author Bernhard Froehler
 * @copyright (C) 2012 Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

jimport('joomla.event.plugin');
jimport('joomla.log.log');

require_once dirname(__FILE__).'/helper.db.php';

class plgSystembfstop extends JPlugin
{

	// default interval used for notifications is one day (in minutes):
	private static $ONE_DAY=1440;
	private $db;
	private $app;
	private static $logCategory = 'bfstop';

	function isLoggingEnabled() {
		return (bool)$this->params->get('loggingEnabled');
	}


	function log($msg, $priority)
	{
		if ($this->isLoggingEnabled())
		{
			JLog::add($msg, $priority, self::$logCategory);
		}
	}

	function plgSystembfstop(& $subject, $config) 
	{
		parent::__construct($subject, $config);
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
		return !$this->db->moreThanGivenEvents($interval, $maxNumber, $logtime, '', $table, $timecol);
	}


	function getBlockedBody($logEntry, $interval)
	{
		return JText::sprintf('BLOCKED_IP_ADDRESS_BODY',
			$logEntry->ipaddress,
			$this->db->getFormattedFailedList($logEntry->ipaddress,
				$logEntry->logtime,
				$interval
			)
		);
	}


	function block($logEntry, $interval)
	{
		$blockEnabled  = (bool)$this->params->get('blockEnabled');
		if (!$blockEnabled) {
			return;
		}
		// if the IP address is blocked we actually shouldn't be here in the first place
		// I guess, but just to make sure
		$blockDuration = (int) $this->params->get('blockDuration');
		if ($this->db->isIPBlocked($logEntry->ipaddress, $blockDuration))
		{
			$this->log('IP '.$logEntry->ipaddress.' is already blocked!', JLog::WARNING);
			return;
		}

		$this->db->blockIP($logEntry);

		$this->log('Inserted IP address '.$logEntry->ipaddress.' into block list', JLog::INFO);
		// send email notification if not too many notifications already...
		$interval  = self::$ONE_DAY;
		$maxNumber = $this->params->get('notifyBlockedNumber');
		if ($this->isNotificationAllowed(
			$logEntry->logtime, $interval, $maxNumber,
			'#__bfstop_bannedip', 'crdate'))
		{
			$body = $this->getBlockedBody($logEntry, $interval);
			$subject = JText::sprintf('BLOCKED_IP_ADDRESS_SUBJECT', $logEntry->ipaddress);
			$this->sendMailNotification($subject, $body);
		}
	}

	function getBlockInterval()
	{
		return min( 1440, (int) $this->params->get('blockDuration'));
	}

	function blockIfTooManyAttempts($logEntry)
	{
		$interval = $this->getBlockInterval();
		$maxNumber = (int)$this->params->get('blockNumber');
		// -1 to block for the blockNumber'th time already
		if (!$this->db->moreThanGivenEvents($interval, $maxNumber-1, $logEntry->logtime,
			" AND t.ipaddress='".$logEntry->ipaddress."'".
			" AND NOT exists (SELECT 1 FROM #__bfstop_lastlogin u".
			" WHERE u.username = t.username ".
			"     AND u.ipaddress = t.ipaddress ".
			"     AND u.logtime > t.logtime)")) {
			return;
		}
		$this->block($logEntry, $interval);
	}

	function getFailedLoginBody($logEntry)
	{
		$bodys = JText::sprintf('FAILED_LOGIN_ATTEMPT', JURI::root()) ."\n";
		$bodys.= str_pad(JText::_('USERNAME').":",15)  . $logEntry->username  ."\n";
		$bodys.= str_pad(JText::_('IPADDRESS').":",15) . $logEntry->ipaddress ."\n";
		$bodys.= str_pad(JText::_('ERROR').":",15)     . $logEntry->error     ."\n";
		$bodys.= str_pad(JText::_('DATETIME').":",15)  . $logEntry->logtime   ."\n";
		$bodys.= str_pad(JText::_('ORIGIN').":",15)    . $this->db->getClientString($logEntry->origin)."\n";
		return $bodys;
	}
	
	function sendMailNotification($subject, $body)
	{
		if((int)$this->params->get( 'emailtype' ) == 1)
		{
			$emailAddress = $this->params->get('emailaddress');
		}
		else if((int)$this->params->get( 'emailtype' ) == 0)
		{
			$uid = $this->params->get('userIDs');
			$emailAddress = $this->db->getEmailAddress($uid);
		}
		else
		{
			$this->log('Invalid source for retrieval of email address!', JLog::ERROR);
			return;
		}
		if (!isset($emailAddress) || strcmp($emailAddress, '') == 0)
		{
			$this->log('No user selected or no email address specified!', JLog::ERROR);
			return;
		}
		$response->error_message = '';
		$mail =& JFactory::getMailer();
		$mail->setSubject($subject);
		$mail->setBody($body);
		$mail->addRecipient($emailAddress);
		$sendSuccess = $mail->Send();
		$this->log('Sent email to '.$emailAddress.', subject: '.$subject.'; '.
			(($sendSuccess)?'successful':'not successful: '.json_encode($mail->ErrorInfo)), JLog::INFO);
	}

	function getIPAddr()
	{
		return getenv('REMOTE_ADDR');
	}
	
	private function init()
	{
		if ($this->isLoggingEnabled())
		{
			JLog::addLogger(array(
				'text_file' => 'plg_system_bfstop.log.php'
			), JLog::ALL,
			self::$logCategory);
		}
		$this->db  = BFStopDBHelper::getInstance();
		$this->app = JFactory::getApplication();
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
		$logEntry->origin    = $this->app->getClientId();

		$this->log('Failed login attempt from IP address '.$logEntry->ipaddress, JLog::DEBUG);
	
		// insert into log:
		$this->db->insertFailedLogin($logEntry);

		// client ID's: 0-frontend, 1-backend
		// for our purpose (bitmask), we need 1-frontend 2-backend
		$interval  = self::$ONE_DAY;
		$maxNumber = (int)$this->params->get('notifyFailedNumber');
		// remaining attempts notification only makes sense if we even do block...
		if ( (bool)$this->params->get('blockEnabled') &&
			(bool)$this->params->get('notifyRemainingAttempts') )
		{
			$attemptsLeft = (int)$this->params->get('blockNumber') 
				- $this->db->getNumberOfFailedLogins(
				$this->getBlockInterval(),
				$logEntry->ipaddress, $logEntry->logtime);
			$application = JFactory::getApplication();
			$application->enqueueMessage(JText::sprintf("X_ATTEMPTS_LEFT", $attemptsLeft));
		}
		if( $this->isNotificationAllowed($logEntry->logtime, $interval, $maxNumber))
		{
			$body = $this->getFailedLoginBody($logEntry);
			$subject = JText::sprintf("FAILED_LOGIN_ATTEMPT", JURI::root());
			$this->sendMailNotification($subject, $body);
		}
		$this->blockIfTooManyAttempts($logEntry);
		return true;
	}

	public function OnUserLogin($user, $options)
	{
		$this->init();
		$ipaddress = $this->getIPAddr();
		$logEntry = new stdClass();
		$logEntry->ipaddress = $this->getIPAddr();
		$logEntry->logtime   = date("Y-m-d H:i:s");
		$logEntry->username  = $user['username'];
		$this->log('Successful login by '.$logEntry->username.' from IP address '.$logEntry->ipaddress, JLog::DEBUG);
	
		// insert into log:
		$this->db->insertSuccessLogin($logEntry);
	}

	public function onAfterInitialise()
	{
		$this->init();
		$ipaddress = $this->getIPAddr();
		$blockDuration = (int) $this->params->get('blockDuration');
		if ($this->db->isIPBlocked($ipaddress, $blockDuration))
		{
			$this->log("Blocked IP Address $ipaddress tried to access ".
				$this->db->getClientString($this->app->getClientId()), JLog::INFO );
			JPlugin::loadLanguage('plg_system_bfstop');
			$message = $this->params->get('blockedMessage', JText::_('BLOCKED_IP_MESSAGE'));
			echo $message;
			$this->app = JFactory::getApplication();
			$this->app->close();
			return false;
		}
		return true;
	}

}

