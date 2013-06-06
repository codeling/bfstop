<?php
defined( '_JEXEC' ) or die;

class BFStopNotifier
{
	public static $ONE_DAY=1440;
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
		}
	}

	public function getNotifyAddress()
	{
		return $this->notifyAddress;
	}

	public function getSiteName()
	{
		$config = JFactory::getConfig();
		$siteName = $config->get('sitename');	// Joomla! 3.x
		$siteName = (strcmp($siteName,'') == 0) ? $config->get('config.sitename') : $siteName;
		return $siteName;
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
		return $this->db->eventsInInterval(
			self::$ONE_DAY, $logtime, '', $table, $timecol)
			< $maxNumber;
	}

	function getBlockedBody($logEntry, $interval)
	{
		return JText::sprintf('BLOCKED_IP_ADDRESS_BODY',
			$logEntry->ipaddress,
			JURI::root(),
			$this->db->getFormattedFailedList($logEntry->ipaddress,
				$logEntry->logtime,
				$interval
			)
		);
	}

	function getFailedLoginBody($logEntry)
	{
		$bodys = JText::sprintf('FAILED_LOGIN_ATTEMPT',
			$this->getSiteName(),
			JURI::root()) ."\n";
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
		$mail = JFactory::getMailer();
		$mail->setSubject($subject);
		$mail->setBody($body);
		$mail->addRecipient($emailAddress);
		$sendSuccess = $mail->Send();
		$this->logger->log('Sent email to '.$emailAddress.', subject: '.$subject.'; '.
			(($sendSuccess)?'successful':'not successful: '.json_encode($mail->ErrorInfo)), JLog::INFO);
		return $sendSuccess;
	}

	public function failedLogin($logEntry, $maxNumber)
	{
		if (!$this->isNotificationAllowed($logEntry->logtime, $maxNumber))
		{
			return;
		}
		$body = $this->getFailedLoginBody($logEntry);
		$subject = JText::sprintf("FAILED_LOGIN_ATTEMPT",
			$this->getSiteName(),
			JURI::root());
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
		$subject = JText::sprintf('BLOCKED_IP_ADDRESS_SUBJECT',
			$this->getSiteName(),
			$logEntry->ipaddress);
		$this->sendMail($subject, $body, $this->notifyAddress);
	}

	public function sendUnblockMail($username, $unblockLink)
	{
		$userEmail = $this->db->getUserEmailByName($username);
		if ($userEmail != null)
		{
			$this->logger->log("User ".$username." was blocked, sending unblock instructions", JLog::DEBUG);
			$siteName = $this->getSiteName();
			$this->sendMail(
				JText::sprintf('BLOCKED_SUBJECT', $siteName),
				JText::sprintf('BLOCKED_BODY',
					$siteName,
					$unblockLink
				),
				$userEmail);
		} else {
			$this->logger->log("Unknown user (".$username.") blocked, not sending any notifications", JLog::DEBUG);
		}
	}
}

