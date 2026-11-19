<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Helper;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Origin;
use Codeling\Library\Bfstop\Repository\Repositories;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Mail\MailerFactoryInterface;
use Joomla\CMS\Uri\Uri;

class NotifierHelper
{
	public const OneDay = 1440;
	private $logger;
	private $repositories;
	private $notifyAddresses;

	public function __construct(LoggerHelper $logger, Repositories $repositories, $emailAddress, $userID, $userGroup, $groupNotifEnabled)
	{
		$this->logger = $logger;
		$this->repositories = $repositories;

		$addresses = empty($emailAddress) ? array() : explode(";", $emailAddress);
		// -1: no user chosen, nothing to look up
		$userEmail = (int) $userID > 0 ? $this->repositories->users()->emailById($userID) : null;
		if (!empty($userEmail))
		{
			$addresses[] = $userEmail;
		}
		if ($groupNotifEnabled)
		{
			$addresses = array_merge($addresses, $this->repositories->users()->emailsOfGroup($userGroup));
		}
		$this->notifyAddresses = self::validAddresses($addresses, $logger);
		if (count($this->notifyAddresses) == 0)
		{
			$this->logger->log('No notification address specified!', Log::DEBUG);
		}
	}

	/**
	 * $addresses without surrounding white space, duplicates and what isn't
	 * an email address (which is logged). The mailer throws for an invalid
	 * recipient - in the request of a failed login, an error page.
	 *
	 * @return string[]
	 */
	public static function validAddresses(array $addresses, ?LoggerHelper $logger = null)
	{
		$valid = array();
		foreach ($addresses as $address)
		{
			$address = trim((string) $address);
			if ($address === '')
			{
				continue;
			}
			if (filter_var($address, FILTER_VALIDATE_EMAIL) === false)
			{
				if ($logger !== null)
				{
					$logger->log('Not a valid email address, not notifying it: '.$address, Log::WARNING);
				}
				continue;
			}
			if (!in_array(strtolower($address), array_map('strtolower', $valid), true))
			{
				$valid[] = $address;
			}
		}
		return $valid;
	}

	public function getNotifyAddresses()
	{
		return $this->notifyAddresses;
	}

	public function getSiteName()
	{
		return (string) Factory::getApplication()->get('sitename');
	}

	/**
	 * The site's address for the mails, if it is configured ($live_site in
	 * configuration.php). The mails are sent from the request of a failed
	 * login, and without $live_site, Joomla builds every address (also
	 * Uri::root()) from the host that request names - which whoever sends it
	 * picks: a link in a genuine mail of the site to their server.
	 */
	public static function siteAddress()
	{
		return trim((string) Factory::getApplication()->get('live_site', '')) !== ''
			? Uri::root()
			: Text::_('PLG_SYSTEM_BFSTOP_SITE_ADDRESS_NOT_SET');
	}

	/**
	 * Whether another notification may be sent: at most $maxNumber of failed
	 * logins (or, with $blocks, of blocks) in the last day, -1 for any number,
	 * 0 for none.
	 */
	public function isNotificationAllowed($logtime, $maxNumber, $blocks = false)
	{
		// -1 stands for an unlimited number of notifications
		if ($maxNumber == -1)
		{
			return true;
		}
		// 0 stands for no notifications
		elseif ($maxNumber == 0)
		{
			return false;
		}
		$events = $blocks
			? $this->repositories->blocks()->countCreatedInWindow($logtime, self::OneDay)
			: $this->repositories->failedLogins()->countInWindow($logtime, self::OneDay);
		return $events <= $maxNumber;
	}

	/**
	 * The failed logins from $ipAddress in the $interval minutes up to
	 * $curTime, as the table in the body of a mail.
	 */
	public function failedLoginList($ipAddress, $curTime, $interval)
	{
		$entries = $this->repositories->failedLogins()->listFromAddress($ipAddress, $curTime, $interval);
		$result = str_pad(Text::_('PLG_SYSTEM_BFSTOP_USERNAME'), 25)." ".
				str_pad(Text::_('PLG_SYSTEM_BFSTOP_IPADDRESS'), 15)." ".
				str_pad(Text::_('PLG_SYSTEM_BFSTOP_DATETIME'), 20)." ".
				str_pad(Text::_('PLG_SYSTEM_BFSTOP_ORIGIN'), 8)."\n".
				str_repeat("-", 97)."\n";
		foreach ($entries as $entry)
		{
			$result .= str_pad(LoggerHelper::singleLine($entry->username), 25)." ".
				str_pad($entry->ipaddress, 15)." ".
				str_pad($entry->logtime, 20)." ".
				str_pad(Origin::name($entry->origin), 8)."\n";
		}
		return $result;
	}

	public function getBlockedBody($logEntry, $interval)
	{
		return Text::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_IP_ADDRESS_BODY',
			$logEntry->ipaddress,
			self::siteAddress(),
			$this->failedLoginList($logEntry->ipaddress,
				$logEntry->logtime,
				$interval
			)
		);
	}

	public function getFailedLoginBody($logEntry)
	{
		$bodys = Text::sprintf('PLG_SYSTEM_BFSTOP_FAILED_LOGIN_ATTEMPT',
			$this->getSiteName(),
			self::siteAddress())."\n";
		$bodys .= str_pad(Text::_('PLG_SYSTEM_BFSTOP_USERNAME').":", 15).
			LoggerHelper::singleLine($logEntry->username)."\n";
		$bodys .= str_pad(Text::_('PLG_SYSTEM_BFSTOP_IPADDRESS').":", 15).
			$logEntry->ipaddress."\n";
		$bodys .= str_pad(Text::_('PLG_SYSTEM_BFSTOP_DATETIME').":", 15).
			$logEntry->logtime."\n";
		$bodys .= str_pad(Text::_('PLG_SYSTEM_BFSTOP_ORIGIN').":", 15).
			Origin::name($logEntry->origin)."\n";
		return $bodys;
	}

	public function sendMail($subject, $body, $emailAddresses)
	{
		if (!is_array($emailAddresses) || count($emailAddresses) == 0)
		{
			$this->logger->log("sendMail called with invalid argument: ".print_r($emailAddresses, true), Log::ERROR);
			return false;
		}
		// everything in the try: the mailer throws for an invalid recipient
		// too, and this runs in the request of a failed login
		try
		{
			$mail = Factory::getContainer()->get(MailerFactoryInterface::class)->createMailer();
			$mail->setSubject($subject);
			$mail->setBody($body);
			foreach ($emailAddresses as $recipient)
			{
				$mail->addRecipient($recipient);
			}
			$sendResult = $mail->send();
		}
		catch (\Throwable $e)
		{
			$sendResult = $e->getMessage();
		}
		$success = ($sendResult === true);
		$this->logger->log('Sent email to '.implode(", ", $emailAddresses).
			', subject: '.$subject.'; '.($success
				? 'successful'
				: 'not successful: '.$sendResult
				), $success ? Log::INFO : Log::ERROR);
		return $sendResult;
	}

	public function failedLogin($logEntry, $maxNumber)
	{
		if (!$this->isNotificationAllowed($logEntry->logtime, $maxNumber))
		{
			return;
		}
		$body = $this->getFailedLoginBody($logEntry);
		$subject = Text::sprintf("PLG_SYSTEM_BFSTOP_FAILED_LOGIN_ATTEMPT",
			$this->getSiteName(),
			self::siteAddress());
		$this->sendMail($subject, $body, $this->notifyAddresses);
	}

	public function blockedNotifyAdmin($logEntry, $interval, $maxNumber)
	{
		if (!$this->isNotificationAllowed($logEntry->logtime, $maxNumber, true))
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
