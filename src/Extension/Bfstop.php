<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Extension;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use Codeling\Plugin\System\Bfstop\Helper\NotifierHelper;
use Codeling\Plugin\System\Bfstop\Helper\TokenHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Uri\Uri;
use Joomla\Event\SubscriberInterface;

class Bfstop extends CMSPlugin implements SubscriberInterface
{
	protected $autoloadLanguage = true;

	private LoggerHelper $logger;
	private NotifierHelper $notifier;
	private DatabaseHelper $mydb;

	public static function getSubscribedEvents(): array
	{
		return array(
			'onUserLoginFailure' => 'onUserLoginFailure',
			'onUserLogin'        => 'onUserLogin',
			'onAfterInitialise'  => 'onAfterInitialise',
		);
	}

	private function getBoolParam($paramName, $default)
	{
		return (bool) $this->params->get($paramName, $default);
	}

	private function getIntParam($paramName, $default)
	{
		return (int) $this->params->get($paramName, $default);
	}

	private function getStringParam($paramName, $default)
	{
		return $this->params->get($paramName, $default);
	}

	private static function endsWith($haystack, $needle)
	{
		$length = strlen($needle);
		if ($length == 0)
		{
			return true;
		}
		return (substr($haystack, -$length) === $needle);
	}

	private function getUnblockLink($id)
	{
		$token = $this->mydb->getNewUnblockToken($id,
			TokenHelper::getToken($this->logger));
		$link = 'index.php?option=com_bfstop'.
			'&view=tokenunblock'.
			'&token='.$token;
		$linkBase = Uri::base();
		// strip off an eventual administrator - tokenunblock is a site view
		$adminDir = 'administrator/';
		if (self::endsWith($linkBase, $adminDir))
		{
			$linkBase = substr($linkBase, 0,
				strlen($linkBase) - strlen($adminDir));
		}
		return $linkBase.$link;
	}

	private function getPasswordResetLink()
	{
		return Route::_('index.php?option=com_users&view=reset');
	}

	private function block($logEntry, $duration)
	{
		$blockEnabled = $this->getBoolParam('blockEnabled', true);
		if (!$blockEnabled)
		{
			return;
		}
		// if the IP address is blocked we actually shouldn't be here in
		// the first place I guess, but just to make sure
		if ($this->mydb->isIPBlocked($logEntry->ipaddress))
		{
			$this->logger->log('IP '.$logEntry->ipaddress.
				' is already blocked!', Log::ERROR);
			return;
		}
		$maxBlocksBefore = $this->getIntParam('maxBlocksBefore', 0);
		if ($maxBlocksBefore > 0)
		{
			$numberOfPrevBlocks = $this->mydb->
				getNumberOfPreviousBlocks($logEntry->ipaddress);
			$this->logger->log('Number of previous blocks for IP='.
				$logEntry->ipaddress.': '.$numberOfPrevBlocks,
				Log::DEBUG);
			if ($numberOfPrevBlocks >= $maxBlocksBefore)
			{
				$this->logger->log('Number of previous blocks '.
					'exceeds configured maximum, blocking '.
					'permanently!', Log::INFO);
				$duration = 0;
			}
		}
		$usehtaccess = $this->getBoolParam('useHtaccess', false);
		$htaccessPath = $this->getStringParam('htaccessPath', JPATH_ROOT);
		if ($htaccessPath === "")
		{
			$this->logger->log('htaccessPath empty, setting it to '.JPATH_ROOT, Log::INFO);
			$htaccessPath = JPATH_ROOT;
		}
		$id = $this->mydb->blockIP($logEntry, $duration, $usehtaccess, $htaccessPath);

		$this->logger->log('Inserted IP address '.$logEntry->ipaddress.
			' into block list', Log::INFO);
		// send email notification to admin
		$this->notifier->blockedNotifyAdmin($logEntry,
			$this->getRealDurationFromDBDuration($duration),
			$this->getIntParam('notifyBlockedNumber', 5));
		if ($this->getBoolParam('notifyBlockedUser', false))
		{
			$userEmail = $this->mydb->getUserEmailByName($logEntry->username);
			if ($userEmail != null)
			{
				$this->logger->log("Existing user '".
					$logEntry->username.
					"' was blocked, sending unblock ".
					"instructions",
					Log::INFO);
				$this->notifier->sendUnblockMail($userEmail,
					$this->getUnblockLink($id));
			}
			else
			{
				$this->logger->log('Unknown user ('.
					$logEntry->username.
					') blocked, not sending any '.
					'notifications', Log::DEBUG);
			}
		}
	}

	private function getRealDurationFromDBDuration($duration)
	{
		return ($duration <= 0)
			? DatabaseHelper::$UNLIMITED_DURATION
			: $duration;
	}

	private function blockIfTooManyAttempts($logEntry)
	{
		$blockInterval = $this->getIntParam('blockDuration', NotifierHelper::$ONE_DAY);
		$maxNumber = $this->getIntParam('blockNumber', 15);
		$checkInterval = $this->getRealDurationFromDBDuration(
			$this->getIntParam('checkInterval', NotifierHelper::$ONE_DAY));
		if ($this->mydb->getNumberOfFailedLogins(
			$checkInterval,
			$logEntry->ipaddress,
			$logEntry->logtime) < $maxNumber)
		{
			return;
		}
		$this->block($logEntry, $blockInterval);
	}

	private function init()
	{
		$this->logger = new LoggerHelper($this->getIntParam('logLevel', LoggerHelper::Disabled));
		$this->mydb = new DatabaseHelper($this->logger);
		$this->notifier = new NotifierHelper($this->logger, $this->mydb,
			$this->params->get('emailaddress', ''),
			$this->getIntParam('userID', -1),
			$this->getIntParam('userGroup', -1),
			$this->getBoolParam('groupNotificationEnabled', false));
	}

	private function notifyOfRemainingAttempts($logEntry)
	{
		// remaining attempts notification only makes sense if we
		// actually block
		$notifyRemaining = $this->getBoolParam('notifyRemainingAttempts', false);
		$passwordReminder = $this->getIntParam('notifyUsePasswordReminder', -1);
		if (!$this->getBoolParam('blockEnabled', true) ||
			(!$notifyRemaining &&
			  !($passwordReminder == -1 || $passwordReminder > 0)))
		{
			// avoid database access if reminders are disabled anyway
			return;
		}
		$allowedAttempts = $this->getIntParam('blockNumber', 15);
		$checkInterval = $this->getRealDurationFromDBDuration(
			$this->getIntParam('checkInterval', NotifierHelper::$ONE_DAY));
		$numberOfFailedLogins = $this->mydb->getNumberOfFailedLogins(
			$checkInterval,
			$logEntry->ipaddress, $logEntry->logtime);
		$attemptsLeft = $allowedAttempts - $numberOfFailedLogins;
		$this->logger->log("Failed logins: $numberOfFailedLogins; ".
			"allowed: $allowedAttempts", Log::DEBUG);
		if ($attemptsLeft < 0)
		{
			$this->logger->log('Remaining attempts below zero ('.
				$attemptsLeft.'), that should not happen. ',
				Log::ERROR);
			return;
		}
		$app = $this->getApplication();
		if ($notifyRemaining && $attemptsLeft > 0)
		{
			$app->enqueueMessage(Text::sprintf(
				"PLG_SYSTEM_BFSTOP_X_ATTEMPTS_LEFT", $attemptsLeft),
				'warning');
		}
		if ($passwordReminder == -1 || $attemptsLeft <= $passwordReminder)
		{
			$resetLink = $this->getPasswordResetLink();
			$app->enqueueMessage(Text::sprintf(
				"PLG_SYSTEM_BFSTOP_PASSWORD_RESET_RECOMMENDED",
				$resetLink), 'warning');
		}
	}

	private function isEnabledForCurrentOrigin()
	{
		$enabledFor = $this->getIntParam('enabledForOrigin', 3);
		return (($enabledFor & ($this->getApplication()->getClientId() + 1)) != 0);
	}

	private function determineDelayDuration()
	{
		$delayDuration = $this->getIntParam('delayDuration', 0);
		$adaptive = $this->getBoolParam('adaptiveDelay', false);
		if ($adaptive)
		{
			$maxDelay = $this->getIntParam('adaptiveDelayMax', 60);
			$lowThreshold = $this->getIntParam('adaptiveDelayThresholdMin', 50);
			$highThreshold = $this->getIntParam('adaptiveDelayThresholdMax', 1000);
			if ($lowThreshold > $highThreshold)
			{
				$tmp = $lowThreshold;
				$lowThreshold = $highThreshold;
				$highThreshold = $tmp;
				$this->logger->log('Lower threshold is configured to a smaller value than higher threshold!'.
					' Please correct! Swapping the values for now!',
					Log::WARNING);
			}
			if ($lowThreshold == $highThreshold)
			{
				$this->logger->log('Lower and higher threshold cannot be configured to the same value!'.
					' Either disable adaptive delay and use the delay duration instead, or'.
					' set the thresholds to reasonable values! Using delay duration for now',
					Log::WARNING);
				return $delayDuration;
			}

			$recentFailed = $this->mydb->getFailedLoginsInLastHour();
			$recentFailed = min($recentFailed, $highThreshold);
			if ($recentFailed > $lowThreshold)
			{
				return $delayDuration + ($recentFailed - $lowThreshold)
					* ($maxDelay - $delayDuration)
					/ ($highThreshold - $lowThreshold);
			}
		}
		return $delayDuration;
	}

	public function onUserLoginFailure($event)
	{
		$user = $event->getArgument(0);
		$this->init();
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		$ipAddress = IpHelper::getAddress($this->logger);
		if (empty($ipAddress) || $ipAddress === '')
		{
			$this->logger->log('Empty IP address!', Log::ERROR);
			return;
		}
		if ($this->mydb->isIPOnAllowList($ipAddress))
		{
			$this->logger->log('Ignoring failed login by allowed address '.$ipAddress, Log::INFO);
			return;
		}
		$delayDuration = $this->determineDelayDuration();
		if ($delayDuration != 0)
		{
			sleep($delayDuration);
		}

		$logEntry = new \stdClass();
		$logEntry->id = null;
		$logEntry->ipaddress = $ipAddress;
		$logEntry->logtime = date("Y-m-d H:i:s");
		$logEntry->username = mb_strimwidth($user['username'], 0, 150, "...");
		$logEntry->origin = $this->getApplication()->getClientId();

		$this->logger->log('Failed login attempt from IP address '.
			$logEntry->ipaddress, Log::DEBUG);

		// insert into log:
		$this->mydb->insertFailedLogin($logEntry);

		$this->notifyOfRemainingAttempts($logEntry);

		$maxNumber = $this->getIntParam('notifyFailedNumber', 0);
		$this->notifier->failedLogin($logEntry, $maxNumber);
		$this->blockIfTooManyAttempts($logEntry);
	}

	public function onUserLogin($event)
	{
		$user = $event->getArgument(0);
		$this->init();
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		$info = new \stdClass();
		$info->ipaddress = IpHelper::getAddress($this->logger);
		$info->username = $user['username'];
		$this->logger->log('Successful login by '.$info->username.
			' from IP address '.$info->ipaddress, Log::DEBUG);
		$this->mydb->successfulLogin($info);
	}

	private function isUnblockRequest()
	{
		$input = $this->getApplication()->input;
		$view = $input->getString('view', '');
		$token = $input->getString('token', '');
		$result = (strcmp($view, "tokenunblock") == 0 &&
			$this->mydb->unblockTokenExists($token));
		if ($result)
		{
			$this->logger->log('Seeing valid unblock token ('.
				$token.'), letting the request pass through '.
				'to com_bfstop',
				Log::INFO);
		}
		return $result;
	}

	public function onAfterInitialise($event)
	{
		$this->init();
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		$purgeAge = $this->getIntParam('deleteOld', 0);
		if ($purgeAge > 0)
		{
			$purgeInterval = 86400; // = 24*60*60 => one day
			$lastPurge = $this->params->get('lastPurge', 0);
			$now = time();
			if ($now > ($lastPurge + $purgeInterval))
			{
				$this->mydb->purgeOldEntries($purgeAge);
				$this->params->set('lastPurge', $now);
				$this->mydb->saveParams($this->params);
			}
		}
		$ipaddress = IpHelper::getAddress($this->logger);
		if ($this->mydb->isIPOnAllowList($ipaddress))
		{
			return;
		}
		if ($this->mydb->isIPBlocked($ipaddress))
		{
			$this->logger->log("Blocked IP Address $ipaddress ".
				"trying to access ".
				$this->mydb->getClientString(
					$this->getApplication()->getClientId()),
				Log::INFO);
			if ($this->isUnblockRequest())
			{
				return;
			}
			if ($this->getBoolParam('useHttpError', false))
			{
				header('HTTP/1.0 403 Forbidden');
			}
			$message = $this->params->get('blockedMessage',
				Text::_('PLG_SYSTEM_BFSTOP_BLOCKED_IP_MESSAGE'));

			if ($this->getBoolParam('blockedMsgShowIP', false))
			{
				$message .= " ".Text::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_CLIENT_IP', $ipaddress);
			}
			echo $message;
			$this->getApplication()->close();
		}
	}
}
