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

	function getBoolParam($paramName, $default)
	{
		return (bool)$this->params->get($paramName, $default);
	}
	function getIntParam($paramName, $default)
	{
		return (int)$this->params->get($paramName, $default);
	}

	function __construct(& $subject, $config) 
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
		$blockEnabled  = $this->getBoolParam('blockEnabled', true);
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
		$maxBlocksBefore = $this->getIntParam('maxBlocksBefore', 0);
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
		$usehtaccess = $this->getBoolParam('useHtaccess', false);
		$id = $this->mydb->blockIP($logEntry, $duration, $usehtaccess);

		$this->logger->log('Inserted IP address '.$logEntry->ipaddress.
			' into block list', JLog::INFO);
		// send email notification to admin
		$this->notifier->blockedNotifyAdmin($logEntry,
			$this->getRealDurationFromDBDuration($duration),
			$this->getIntParam('notifyBlockedNumber', 5));
		if ($this->getBoolParam('notifyBlockedUser', false))
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
		$blockDuration = $this->getIntParam('blockDuration',
			BFStopNotifier::$ONE_DAY);
		return $this->getRealDurationFromDBDuration($blockDuration);
	}

	function blockIfTooManyAttempts($logEntry)
	{
		$interval = $this->getBlockInterval();
		$maxNumber = $this->getIntParam('blockNumber', 15);
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
		// source: http://stackoverflow.com/a/2031935
		$keys = array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR');
		foreach ($keys as $key){
			if (array_key_exists($key, $_SERVER) === true){
				foreach (explode(',', $_SERVER[$key]) as $ip){
					$ip = trim($ip); // just to be safe
					if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false){
						return $ip;
					}
				}
			}
		}
		$this->logger->log('No proper remote IP address available, falling back to REMOTE_ADDR "'.$_SERVER['REMOTE_ADDR'].
			'"!', JLog::WARNING);
		// possibly we should instead stop processing in case no proper IP address can be determined
		return $_SERVER['REMOTE_ADDR'];
	}
	
	private function init()
	{
		$this->logger = new BFStopLogger($this->getIntParam(
			'logLevel', BFStopLogger::Disabled));
		$this->mydb  = new BFStopDBHelper($this->logger);
		$this->notifier = new BFStopNotifier($this->logger, $this->mydb,
			$this->params->get('emailaddress', ''),
			$this->getIntParam('userID', -1),
			$this->getIntParam('userGroup', -1),
			$this->getBoolParam('groupNotificationEnabled', false));
		$this->myapp = JFactory::getApplication();
	}

	function notifyOfRemainingAttempts($logEntry)
	{
		// remaining attempts notification only makes sense if we
		// actually block
		$notifyRemaining = $this->getBoolParam('notifyRemainingAttempts',
			false);
		$passwordReminder = $this->getIntParam('notifyUsePasswordReminder',
			-1);
		if ( !$this->getBoolParam('blockEnabled', true) ||
			 (!$notifyRemaining &&
			  !($passwordReminder == -1 || $passwordReminder > 0)))
		{
			// avoid database access if reminders are disabled anyway
			return;
		}
		$allowedAttempts = $this->getIntParam('blockNumber', 15);
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
		if ($this->getBoolParam('notifyRemainingAttempts', false) &&
			$attemptsLeft > 0) {
			$this->myapp->enqueueMessage(JText::sprintf(
				"PLG_SYSTEM_BFSTOP_X_ATTEMPTS_LEFT", $attemptsLeft));
		}
		if ($passwordReminder == -1 || $attemptsLeft <= $passwordReminder)
		{
			$resetLink = $this->getPasswordResetLink();
			$this->myapp->enqueueMessage(JText::sprintf(
				"PLG_SYSTEM_BFSTOP_PASSWORD_RESET_RECOMMENDED",
				$resetLink));
		}
	}

	public function isEnabledForCurrentOrigin()
	{
		$enabledFor = $this->getIntParam('enabledForOrigin', 3);
		return ( ($enabledFor & ($this->myapp->getClientId()+1)) != 0);
	}

	public function determineDelayDuration()
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
		$ipAddress = $this->getIPAddr();
		if (empty($ipAddress) || $ipAddress === '')
		{
			$this->logger->log('Empty IP address!', JLog::ERROR);
			return;
		}
		if ($this->mydb->isIPWhiteListed($ipAddress))
		{
			$this->logger->log('Ignoring failed login by whitelisted address '.$ipAddress, JLog::INFO);
			return;
		}
		JPlugin::loadLanguage('plg_system_bfstop');
		$delayDuration = $this->determineDelayDuration();
		if ($delayDuration != 0)
		{
			sleep($delayDuration);
		}

		$logEntry = new stdClass();
		$logEntry->id		= null;
		$logEntry->ipaddress = $ipAddress;
		$logEntry->logtime   = date("Y-m-d H:i:s");
		$logEntry->username  = $user['username'];
		$logEntry->origin	= $this->myapp->getClientId();

		$this->logger->log('Failed login attempt from IP address '.
			$logEntry->ipaddress, JLog::DEBUG);
	
		// insert into log:
		$this->mydb->insertFailedLogin($logEntry);

		$this->notifyOfRemainingAttempts($logEntry);

		$maxNumber = $this->getIntParam('notifyFailedNumber', 0);
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
			if ($this->getBoolParam('useHttpError', false))
			{
				header('HTTP/1.0 403 Forbidden');
			}
			$message = $this->params->get('blockedMessage',
				JText::_('PLG_SYSTEM_BFSTOP_BLOCKED_IP_MESSAGE'));

			if ($this->getBoolParam('blockedMsgShowIP', false))
			{
				$message .= " ".JText::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_CLIENT_IP', $ipaddress);
			}
			echo $message;
			$this->myapp->close();
		}
	}
}
