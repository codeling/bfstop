<?php
/*
 * @package Brute Force Stop (bfstop) for Joomla! >=2.5
 * @author Bernhard Froehler
 * @copyright (C) 2012-2014 Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined( '_JEXEC' ) or die;

class BFStopNotifier
{
	public static $ONE_DAY=1440;
	private $logger;
	private $db;
	private $notifyAddresses;

	function __construct($logger, $db, $emailAddress, $userID, $userGroup, $groupNotifEnabled)
	{
		$this->logger = $logger;
		$this->db = $db;

		$this->notifyAddresses = empty($emailAddress)? array() : explode(";",$emailAddress);
		$userEmail = $this->db->getUserEmailByID($userID);
		if (!empty($userEmail))
		{
			$this->notifyAddresses = array_merge($this->notifyAddresses, array($userEmail));
		}
		if ($groupNotifEnabled)
		{
			$this->notifyAddresses = array_merge($this->notifyAddresses, $this->db->getUserGroupEmail($userGroup));
		}
		if (count($this->notifyAddresses) == 0)
		{
			$this->logger->log('No notification address specified!', JLog::DEBUG);
		}
	}

	public function getNotifyAddresses()
	{
		return $this->notifyAddresses;
	}

	public function getSiteName()
	{
		$config = JFactory::getConfig();
		$siteName = $config->get('sitename');	// Joomla! 3.x
		$siteName = (strcmp($siteName,'') == 0)
			? $config->get('config.sitename')
			: $siteName;
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
			<= $maxNumber;
	}

	function getBlockedBody($logEntry, $interval)
	{
		return JText::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_IP_ADDRESS_BODY',
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
		$bodys = JText::sprintf('PLG_SYSTEM_BFSTOP_FAILED_LOGIN_ATTEMPT',
			$this->getSiteName(),
			JURI::root()) ."\n";
		$bodys.= str_pad(JText::_('PLG_SYSTEM_BFSTOP_USERNAME').":",15) .
			$logEntry->username  ."\n";
		$bodys.= str_pad(JText::_('PLG_SYSTEM_BFSTOP_IPADDRESS').":",15).
			$logEntry->ipaddress ."\n";
		$bodys.= str_pad(JText::_('PLG_SYSTEM_BFSTOP_DATETIME').":",15) .
			$logEntry->logtime   ."\n";
		$bodys.= str_pad(JText::_('PLG_SYSTEM_BFSTOP_ORIGIN').":",15)   .
			$this->db->getClientString($logEntry->origin)."\n";
		return $bodys;
	}

	function sendMail($subject, $body, $emailAddresses)
	{
		if (!is_array($emailAddresses) || count($emailAddresses) == 0)
		{
			$this->logger->log('Sending email failed: At least one email address is required, none given.', JLog::ERROR);
			return;
		}
		$mail = JFactory::getMailer();
		$mail->setSubject($subject);
		$mail->setBody($body);
		foreach ($emailAddresses as $recipient)
		{
			$mail->addRecipient($recipient);
		}
		$sendResult = $mail->Send();
		$sendSuccess = ($sendResult === true);
		$this->logger->log('Sent email to '.implode(", ", $emailAddresses).
			', subject: '.$subject.'; '.(($sendSuccess)
				? 'successful'
				:'not successful: '.
				json_encode($mail->ErrorInfo)), JLog::INFO);
		return $sendSuccess;
	}

	public function failedLogin($logEntry, $maxNumber)
	{
		if (!$this->isNotificationAllowed($logEntry->logtime,
			$maxNumber))
		{
			return;
		}
		$body = $this->getFailedLoginBody($logEntry);
		$subject = JText::sprintf("PLG_SYSTEM_BFSTOP_FAILED_LOGIN_ATTEMPT",
			$this->getSiteName(),
			JURI::root());
		$this->sendMail($subject, $body, $this->notifyAddresses);
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
		$subject = JText::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_IP_ADDRESS_SUBJECT',
			$this->getSiteName(),
			$logEntry->ipaddress);
		$this->sendMail($subject, $body, $this->notifyAddresses);
	}

	public function sendUnblockMail($userEmail, $unblockLink)
	{
		$siteName = $this->getSiteName();
		$this->sendMail(
			JText::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_SUBJECT', $siteName),
			JText::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_BODY',
				$siteName,
				$unblockLink
			),
			$userEmail);
	}
}

