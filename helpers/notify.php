<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined( '_JEXEC' ) or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Uri\Uri;

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
			$this->logger->log('No notification address specified!', Log::DEBUG);
		}
	}

	public function getNotifyAddresses()
	{
		return $this->notifyAddresses;
	}

	public function getSiteName()
	{
		$config = Factory::getConfig();
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
		return Text::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_IP_ADDRESS_BODY',
			$logEntry->ipaddress,
			Uri::root(),
			$this->db->getFormattedFailedList($logEntry->ipaddress,
				$logEntry->logtime,
				$interval
			)
		);
	}

	function getFailedLoginBody($logEntry)
	{
		$bodys = Text::sprintf('PLG_SYSTEM_BFSTOP_FAILED_LOGIN_ATTEMPT',
			$this->getSiteName(),
			Uri::root()) ."\n";
		$bodys.= str_pad(Text::_('PLG_SYSTEM_BFSTOP_USERNAME').":",15) .
			$logEntry->username  ."\n";
		$bodys.= str_pad(Text::_('PLG_SYSTEM_BFSTOP_IPADDRESS').":",15).
			$logEntry->ipaddress ."\n";
		$bodys.= str_pad(Text::_('PLG_SYSTEM_BFSTOP_DATETIME').":",15) .
			$logEntry->logtime   ."\n";
		$bodys.= str_pad(Text::_('PLG_SYSTEM_BFSTOP_ORIGIN').":",15)   .
			$this->db->getClientString($logEntry->origin)."\n";
		return $bodys;
	}

	function sendMail($subject, $body, $emailAddresses)
	{
		if (!is_array($emailAddresses) || count($emailAddresses) == 0)
		{
			$this->logger->log("sendMail called with invalid argument: $emailAddresses", Log::ERROR);
			return false;
		}
		$mail = Factory::getMailer();
		$mail->setSubject($subject);
		$mail->setBody($body);
		foreach ($emailAddresses as $recipient)
		{
			$mail->addRecipient($recipient);
		}
		try
		{
			$sendResult = $mail->Send();
		}
		catch (phpmailerException $e)
		{
			$sendResult = $e->errorMessage();
		}
		catch (MailDisabledException $e)
		{
			$sendResult = $e->getReason();
		}
		catch (Exception $e)
		{
			$sendResult = $e->getMessage();
		}
		$success = ($sendResult === true);
		$this->logger->log('Sent email to '.implode(", ", $emailAddresses).
			', subject: '.$subject.'; '.($success
				? 'successful'
				:'not successful: '.$sendResult
				), $success ? Log::INFO : Log::ERROR);
		return $sendResult;
	}

	public function failedLogin($logEntry, $maxNumber)
	{
		if (!$this->isNotificationAllowed($logEntry->logtime,
			$maxNumber))
		{
			return;
		}
		$body = $this->getFailedLoginBody($logEntry);
		$subject = Text::sprintf("PLG_SYSTEM_BFSTOP_FAILED_LOGIN_ATTEMPT",
			$this->getSiteName(),
			Uri::root());
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
		$subject = Text::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_IP_ADDRESS_SUBJECT',
			$this->getSiteName(),
			$logEntry->ipaddress);
		$this->sendMail($subject, $body, $this->notifyAddresses);
	}

	public function sendUnblockMail($userEmail, $unblockLink)
	{
		$siteName = $this->getSiteName();
		$this->sendMail(
			Text::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_SUBJECT', $siteName),
			Text::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_BODY',
				$siteName,
				$unblockLink
			),
			array($userEmail)
		);
	}
}

