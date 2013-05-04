<?php
defined( '_JEXEC' ) or die;
class BFStopNotifier
{
	private static $ONE_DAY=1440;
	private $logger;
	private $db;
	private $notifyAddress;

	function __construct($logger, $db, $config, $emailAddress, $userID)
	{
		$this->logger = $logger;
		$this->db = $db;
		if($config == 1)
		{
		        $this->notifyAddress = $emailAddress;
		}
		else if ($config == 0)
		{
		        $this->notifyAddress = $this->db->getUserEmailByID($userID);
		}
		else
		{
		        $this->logger->log('Invalid source for retrieval of email address!', JLog::ERROR);
		        return;
		}

	}

	function isNotificationAllowed($logtime, $maxNumber,
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
		return !$this->db->moreThanGivenEvents(self::$ONE_DAY, $maxNumber, $logtime, '', $table, $timecol);
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

	function sendMail($subject, $body, $emailAddress)
	{
		if (!isset($emailAddress) || strcmp($emailAddress, '') == 0)
		{
			$this->logger->log('No user selected or no email address specified!', JLog::ERROR);
			return;
		}
		$response->error_message = '';
		$mail =& JFactory::getMailer();
		$mail->setSubject($subject);
		$mail->setBody($body);
		$mail->addRecipient($emailAddress);
		$sendSuccess = $mail->Send();
		$this->logger->log('Sent email to '.$emailAddress.', subject: '.$subject.'; '.
			(($sendSuccess)?'successful':'not successful: '.json_encode($mail->ErrorInfo)), JLog::INFO);
	}

	public function failedLogin($logEntry, $maxNumber)
	{
		if (!$this->isNotificationAllowed($logEntry->logtime, $maxNumber))
		{
			return;
		}
		$body = $this->getFailedLoginBody($logEntry);
		$subject = JText::sprintf("FAILED_LOGIN_ATTEMPT", JURI::root());
		$this->sendMail($subject, $body, $this->notifyAddress);
	}

	public function blockedNotifyAdmin($logEntry, $interval, $maxNumber)
	{
		if (!$this->isNotificationAllowed(
			$logEntry->logtime, $maxNumber,
			'#__bfstop_bannedip', 'crdate'))
		{
			return;
		}
		$body = $this->getBlockedBody($logEntry, $interval);
		$subject = JText::sprintf('BLOCKED_IP_ADDRESS_SUBJECT', $logEntry->ipaddress);
		$this->sendMail($subject, $body, $this->notifyAddress);
	}

}

