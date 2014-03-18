<?php
/*
 * @package Brute Force Stop (bfstop) for Joomla! >=2.5
 * @author Bernhard Froehler
 * @copyright (C) 2012-2014 Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

jimport('joomla.event.plugin');
jimport('joomla.log.log');

require_once dirname(__FILE__).'/helpers/log.php';
require_once dirname(__FILE__).'/helpers/db.php';
require_once dirname(__FILE__).'/helpers/notify.php';
require_once dirname(__FILE__).'/helpers/crypto.php';

class plgSystembfstop extends JPlugin
{
	private $myapp;
	private $mydb;
	private $logger;

	function plgSystembfstop(& $subject, $config) 
	{
		parent::__construct($subject, $config);
	}

	static function endsWith($haystack, $needle)
	{
		$length = strlen($needle);
		if ($length == 0)
		{
			return true;
		}
		return (substr($haystack, -$length) === $needle);
	}

	function getUnblockLink($id)
	{
		$token = $this->mydb->getNewUnblockToken($id,
			BFStopTokenGenerator::getToken($this->logger));
		$link = 'index.php?option=com_bfstop'.
			'&view=tokenunblock'.
			'&token='.$token;
                $linkBase = JURI::base();
		// strip off an eventual administrator - tokenunblock is a site view
		$adminDir = 'administrator/';
		if (self::endsWith($linkBase, $adminDir))
		{
			$linkBase = substr($linkBase, 0,
				strlen($linkBase)-strlen($adminDir));
		}
		return $linkBase.$link;
	}

	function getPasswordResetLink()
	{
		$link = 'index.php?option=com_users&view=reset';
		return JRoute::_($link);
	}

	function block($logEntry, $duration)
	{
		$blockEnabled  = (bool)$this->params->get('blockEnabled', true);
		if (!$blockEnabled) {
			return;
		}
		// if the IP address is blocked we actually shouldn't be here in
		// the first place I guess, but just to make sure
		if ($this->mydb->isIPBlocked($logEntry->ipaddress))
		{
			$this->logger->log('IP '.$logEntry->ipaddress.
				' is already blocked!', JLog::ERROR);
			return;
		}
		$maxBlocksBefore = (int)$this->params->get('maxBlocksBefore', 0);
		if ($maxBlocksBefore > 0)
		{
			$numberOfPrevBlocks = $this->mydb->
				getNumberOfPreviousBlocks($logEntry->ipaddress);
			$this->logger->log('Number of previous blocks for IP='.
				$logEntry->ipaddress.': '.$numberOfPrevBlocks,
				JLog::DEBUG);
			if ($numberOfPrevBlocks >= $maxBlocksBefore)
			{
				$this->logger->log('Number of previous blocks '.
					'exceeds configured maximum, blocking '.
					'permanently!', JLog::INFO);
				$duration = 0;
			}
		}
		$id = $this->mydb->blockIP($logEntry, $duration);

		$this->logger->log('Inserted IP address '.$logEntry->ipaddress.
			' into block list', JLog::INFO);
		// send email notification to admin
		$this->notifier->blockedNotifyAdmin($logEntry,
			$this->getRealDurationFromDBDuration($duration),
			(int)$this->params->get('notifyBlockedNumber', 5));
		if ((bool)$this->params->get('notifyBlockedUser', false))
		{
			$userEmail = $this->mydb->getUserEmailByName(
				$logEntry->username);
			if ($userEmail != null)
			{
				$this->logger->log("Existing user '".
					$logEntry->username.
					"' was blocked, sending unblock ".
					"instructions",
					JLog::INFO);
				$this->notifier->sendUnblockMail($userEmail,
					$this->getUnblockLink($id));
			} else {
				$this->logger->log('Unknown user ('.
					$logEntry->username.
					') blocked, not sending any '.
					'notifications', JLog::DEBUG);
			}
		}
	}

	function getRealDurationFromDBDuration($duration)
	{
		return ($duration <= 0)
			? BFStopDBHelper::$UNLIMITED_DURATION
			: $duration;
	}

	function getDBDuration($duration)
	{
		return ($duration >= BFStopDBHelper::$UNLIMITED_DURATION)
			? 0
			: $duration;
	}

	function getBlockInterval()
	{
		$blockDuration = (int)$this->params->get('blockDuration',
			BFStopNotifier::$ONE_DAY);
		return $this->getRealDurationFromDBDuration($blockDuration);
	}

	function blockIfTooManyAttempts($logEntry)
	{
		$interval = $this->getBlockInterval();
		$maxNumber = (int)$this->params->get('blockNumber', 15);
		if ($this->mydb->getNumberOfFailedLogins(
			$interval,
			$logEntry->ipaddress,
			$logEntry->logtime) < $maxNumber) {
			return;
		}
		$this->block($logEntry, $this->getDBDuration($interval));
	}


	function getIPAddr()
	{
		return $_SERVER['REMOTE_ADDR'];
	}
	
	private function init()
	{
		$this->logger = new BFStopLogger((int)$this->params->get(
			'logLevel', BFStopLogger::Disabled));
		$this->mydb  = new BFStopDBHelper($this->logger);
		$this->notifier = new BFStopNotifier($this->logger, $this->mydb,
			$this->params->get('emailaddress', ''),
			(int)$this->params->get('userID', -1),
			(int)$this->params->get('userGroup', -1),
			(bool)$this->params->get('groupNotificationEnabled', false));
		$this->myapp = JFactory::getApplication();
	}

	function notifyOfRemainingAttempts($logEntry)
	{
		// remaining attempts notification only makes sense if we
		// actually block
		$notifyRemaining = (bool)$this->params->get('notifyRemainingAttempts',
			false);
		$passwordReminder = (int) $this->params->get('notifyUsePasswordReminder',
			-1);
		if ( !(bool)$this->params->get('blockEnabled', true) ||
		     (!$notifyRemaining &&
		      !($passwordReminder == -1 || $passwordReminder > 0)))
		{
			// avoid database access if reminders are disabled anyway
			return;
		}
		$allowedAttempts = (int)$this->params->get('blockNumber', 15);
		$numberOfFailedLogins = $this->mydb->getNumberOfFailedLogins(
			$this->getBlockInterval(),
			$logEntry->ipaddress, $logEntry->logtime);
		$attemptsLeft = $allowedAttempts - $numberOfFailedLogins;
		$this->logger->log("Failed logins: $numberOfFailedLogins; ".
			"allowed: $allowedAttempts", JLog::DEBUG);
		if ($attemptsLeft < 0) {
			$this->logger->log('Remaining attempts below zero ('.
				$attemptsLeft.'), that should not happen. ',
				JLog::ERROR);
			return;
		}
		if ((bool)$this->params->get('notifyRemainingAttempts', false) &&
			$attemptsLeft > 0) {
			$this->myapp->enqueueMessage(JText::sprintf(
				"X_ATTEMPTS_LEFT", $attemptsLeft));
		}
		if ($passwordReminder == -1 || $attemptsLeft <= $passwordReminder)
		{
			$resetLink = $this->getPasswordResetLink();
			$this->myapp->enqueueMessage(JText::sprintf(
				"PASSWORD_RESET_RECOMMENDED",
				$resetLink));
		}
	}

	public function isEnabledForCurrentOrigin()
	{
		$enabledFor = (int)$this->params->get('enabledForOrigin', 3);
		return ( ($enabledFor & ($this->myapp->getClientId()+1)) != 0);
	}

	public function determineDelayDuration()
	{
		$delayDuration = (int)$this->params->get('delayDuration', 0);
		$adaptive = (bool)$this->params->get('adaptiveDelay', false);
		if ($adaptive)
		{
			$maxDelay = (int)$this->params->get('adaptiveDelayMax', 60);
			$lowThreshold = (int)$this->params->get('adaptiveDelayThresholdMin', 50);
			$highThreshold = (int)$this->params->get('adaptiveDelayThresholdMax', 1000);
			if ($lowThreshold > $highThreshold)
			{
				$tmp = $lowThreshold;
				$lowThreshold = $highThreshold;
				$highThreshold = $tmp;
				$this->logger->log('Lower threshold is configured to a smaller value than higher threshold!'.
					' Please correct! Swapping the values for now!',
					JLog::WARNING);
			}
			if ($lowThreshold == $highThreshold)
			{
				$this->logger->log('Lower and higher threshold cannot be configured to the same value!'.
					' Either disable adaptive delay and use the delay duration instead, or'.
					' set the thresholds to reasonable values! Using delay duration for now',
					JLog::WARNING);
				return $delayDuration;
			}

			$recentFailed = $this->mydb->getFailedLoginsInLastHour();
			$recentFailed = min($recentFailed, $highThreshold);
			if ($recentFailed > $lowThreshold)
			{
				$delay = $delayDuration + ($recentFailed-$lowThreshold)
					* ($maxDelay-$delayDuration)
					/ ($highThreshold-$lowThreshold);
				return $delay;
			}
		}
		return $delayDuration;
	}

 	public function onUserLoginFailure($user, $options=null)
	{
		$this->init();
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		if ($this->mydb->isIPWhiteListed($this->getIPAddr()))
		{
			$this->logger->log('Ignoring failed login by whitelisted address '.$this->getIPAddr(), JLog::INFO);
			return;
		}
		JPlugin::loadLanguage('plg_system_bfstop');
		$delayDuration = $this->determineDelayDuration();
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
		$logEntry->origin    = $this->myapp->getClientId();

		$this->logger->log('Failed login attempt from IP address '.
			$logEntry->ipaddress, JLog::DEBUG);
	
		// insert into log:
		$this->mydb->insertFailedLogin($logEntry);

		$this->notifyOfRemainingAttempts($logEntry);

		$maxNumber = (int)$this->params->get('notifyFailedNumber', 0);
		$this->notifier->failedLogin($logEntry, $maxNumber);
		$this->blockIfTooManyAttempts($logEntry);
	}

	public function OnUserLogin($user, $options)
	{
		$this->init();
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		$info = new stdClass();
		$info->ipaddress = $this->getIPAddr();
		$info->username  = $user['username'];
		$this->logger->log('Successful login by '.$info->username.
			' from IP address '.$info->ipaddress, JLog::DEBUG);
		$this->mydb->successfulLogin($info);
	}

	function isUnblockRequest()
	{
		$input = $this->myapp->input;
		$view  = $input->getString('view', '');
		$token = $input->getString('token', '');
		$result = (strcmp($view, "tokenunblock") == 0 &&
			$this->mydb->unblockTokenExists($token));
		if ($result) {
			$this->logger->log('Seeing valid unblock token ('.
				$token.'), letting the request pass through '.
				'to com_bfstop',
				JLog::INFO);
		}
		return $result;
	}

	public function onAfterInitialise()
	{
		$this->init();
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		$purgeAge = (int)$this->params->get('deleteOld', 0);
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
		$ipaddress = $this->getIPAddr();
		if ($this->mydb->isIPWhiteListed($ipaddress))
		{
			return;
		}
		if ($this->mydb->isIPBlocked($ipaddress))
		{
			$this->logger->log("Blocked IP Address $ipaddress ".
				"trying to access ".
				$this->mydb->getClientString(
					$this->myapp->getClientId()),
				JLog::INFO );
			if ($this->isUnblockRequest())
			{
				return;
			}
			JPlugin::loadLanguage('plg_system_bfstop');
			if ((bool)$this->params->get('useHttpError', false))
			{
				header('HTTP/1.0 403 Forbidden');
			}
			$message = $this->params->get('blockedMessage',
				JText::_('BLOCKED_IP_MESSAGE'));

			if ((bool)$this->params->get('blockedMsgShowIP', false))
			{
				$message .= " ".JText::sprintf('BLOCKED_CLIENT_IP', $ipaddress);
			}
			echo $message;
			$this->myapp->close();
		}
	}
}
