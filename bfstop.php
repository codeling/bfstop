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

require_once dirname(__FILE__).'/helpers/log.php';
require_once dirname(__FILE__).'/helpers/db.php';
require_once dirname(__FILE__).'/helpers/notify.php';

class plgSystembfstop extends JPlugin
{
	private $db;
	private $app;
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
		$token = $this->db->getNewUnblockToken($id);
		$link = 'index.php?option=com_bfstop'.
			'&view=tokenunblock'.
			'&token='.$token;
                $linkBase = JURI::base();
		// strip off an eventual administrator - tokenunblock is a site view
		$adminDir = 'administrator/';
		if (self::endsWith($linkBase, $adminDir))
		{
			$linkBase = substr($linkBase, 0, strlen($linkBase)-strlen($adminDir));
		}
		return $linkBase.$link;
	}

	function block($logEntry, $duration)
	{
		$blockEnabled  = (bool)$this->params->get('blockEnabled', true);
		if (!$blockEnabled) {
			return;
		}
		// if the IP address is blocked we actually shouldn't be here in the first place
		// I guess, but just to make sure
		if ($this->db->isIPBlocked($logEntry->ipaddress))
		{
			$this->logger->log('IP '.$logEntry->ipaddress.' is already blocked!', JLog::WARNING);
			return;
		}
		$maxBlocksBefore = $this->params->get('maxBlocksBefore');
		if ($maxBlocksBefore > 0)
		{
			$numberOfPrevBlocks = $this->db->getNumberOfPreviousBlocks($logEntry->ipaddress);
			$this->logger->log('Number of previous blocks for IP='.$logEntry->ipaddress.': '.$numberOfPrevBlocks, JLog::DEBUG);
			if ($numberOfPrevBlocks >= $maxBlocksBefore)
			{
				$this->logger->log('Number of previous blocks exceeds configured maximum, blocking permanently!', JLog::INFO);
				$duration = 0;
			}
		}
		$id = $this->db->blockIP($logEntry, $duration);

		$this->logger->log('Inserted IP address '.$logEntry->ipaddress.' into block list', JLog::INFO);
		// send email notification to admin
		$this->notifier->blockedNotifyAdmin($logEntry,
			$this->getRealDurationFromDBDuration($duration),
			$this->params->get('notifyBlockedNumber', 5));
		if ((bool)$this->params->get('notifyBlockedUser', false))
		{
			$this->notifier->sendUnblockMail($logEntry->username, $this->getUnblockLink($id));
		}
	}

	function getRealDurationFromDBDuration($duration)
	{
		return ($duration <= 0)
			? BFStopDBHelper::$UNLIMITED_DURATION
			: $duration;
	}

	function getBlockInterval($ipaddress)
	{
		$blockDuration = (int)$this->params->get('blockDuration',
			BFStopNotifier::$ONE_DAY);
		return $this->getRealDurationFromDBDuration($blockDuration);
	}

	function blockIfTooManyAttempts($logEntry)
	{
		$interval = $this->getBlockInterval($logEntry->ipaddress);
		$maxNumber = (int)$this->params->get('blockNumber', 15);
		if ($this->db->getNumberOfFailedLogins(
			$interval,
			$logEntry->ipaddress,
			$logEntry->logtime) < $maxNumber) {
			return;
		}
		$this->block($logEntry, $interval);
	}


	function getIPAddr()
	{
		return getenv('REMOTE_ADDR');
	}
	
	private function init()
	{
		$this->logger = new BFStopLogger((int)$this->params->get('logLevel', BFStopLogger::Disabled));
		$this->db  = new BFStopDBHelper($this->logger);
		$this->notifier = new BFStopNotifier($this->logger, $this->db,
			(int)$this->params->get( 'emailtype' ),
			$this->params->get('emailaddress'),
			$this->params->get('userIDs'));
		$this->app = JFactory::getApplication();
	}

	function notifyOfRemainingAttempts($logEntry)
	{
		// remaining attempts notification only makes sense if we even do block...
		if ( !(bool)$this->params->get('blockEnabled', true) ||
			!(bool)$this->params->get('notifyRemainingAttempts', false) )
		{
			return;
		}
		$allowedAttempts = (int)$this->params->get('blockNumber', 15);
		$numberOfFailedLogins = $this->db->getNumberOfFailedLogins(
			$this->getBlockInterval($logEntry->ipaddress),
			$logEntry->ipaddress, $logEntry->logtime);
		$attemptsLeft = $allowedAttempts - $numberOfFailedLogins;
		$this->logger->log("Failed logins: $numberOfFailedLogins; allowed: $allowedAttempts", JLog::DEBUG);
		if ($attemptsLeft < 0) {
			$this->logger->log('Remaining attempts below zero ('.$attemptsLeft.
				'), that should not happen. ',
				JLog::ERROR);
			return;
		}
		if ($attemptsLeft > 0) {
			$this->app->enqueueMessage(JText::sprintf("X_ATTEMPTS_LEFT", $attemptsLeft));
		}
	}

	public function isEnabledForCurrentOrigin()
	{
		$enabledFor = (int)$this->params->get('enabledForOrigin', 3);
		return ( ($enabledFor & ($this->app->getClientId()+1)) != 0);
	}

 	public function onUserLoginFailure($user, $options=null)
	{
		$this->init();
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		JPlugin::loadLanguage('plg_system_bfstop');
		$delayDuration = (int)$this->params->get('delayDuration', 0);
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

		$this->logger->log('Failed login attempt from IP address '.$logEntry->ipaddress, JLog::DEBUG);
	
		// insert into log:
		$this->db->insertFailedLogin($logEntry);

		$this->notifyOfRemainingAttempts($logEntry);

		$maxNumber = (int)$this->params->get('notifyFailedNumber', 0);
		$this->notifier->failedLogin($logEntry, $maxNumber);
		$this->blockIfTooManyAttempts($logEntry);
		return true;
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
		$this->db->successfulLogin($info);
	}

	function isUnblockRequest()
	{
		$input = $this->app->input;
		$view  = $input->getString('view', '');
		$token = $input->getString('token', '');
		$result = (strcmp($view, "tokenunblock") == 0 &&
			$this->db->unblockTokenExists($token));
		if ($result) {
			$this->logger->log('Seeing valid unblock token ('.
				$token.'), letting the request pass through to com_bfstop',
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
		$ipaddress = $this->getIPAddr();
		if ($this->db->isIPBlocked($ipaddress))
		{
			$this->logger->log("Blocked IP Address $ipaddress trying to access ".
				$this->db->getClientString($this->app->getClientId()),
				JLog::INFO );
			if ($this->isUnblockRequest())
			{
				return;
			}
			JPlugin::loadLanguage('plg_system_bfstop');
			$message = $this->params->get('blockedMessage', JText::_('BLOCKED_IP_MESSAGE'));
			echo $message;
			$this->app->close();
		}
	}
}
