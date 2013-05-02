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

require_once dirname(__FILE__).'/helper.log.php';
require_once dirname(__FILE__).'/helper.db.php';
require_once dirname(__FILE__).'/helper.notify.php';

class plgSystembfstop extends JPlugin
{

	// default interval used for notifications is one day (in minutes):
	private $db;
	private $app;
	private $logger;

	function plgSystembfstop(& $subject, $config) 
	{
		parent::__construct($subject, $config);
	}


	function getUnblockLink($id)
	{
		$token = $this->db->getNewUnblockToken($id);
		$link = 'index.php?option=com_bfstop'.
			'&task=tokenunblock'.
			'&token='.$token;
		return JRoute::_($link, true, -1);
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
			$this->logger->log('IP '.$logEntry->ipaddress.' is already blocked!', JLog::WARNING);
			return;
		}

		$id = $this->db->blockIP($logEntry);

		$this->logger->log('Inserted IP address '.$logEntry->ipaddress.' into block list', JLog::INFO);
		// send email notification to admin
		$this->notifier->blockedNotifyAdmin($logEntry, $blockDuration, $this->params->get('notifyBlockedNumber'));
		if ($this->params->get('notifyBlockedUser'))
		{
			$userEmail = $this->db->getUserEmailByName($logEntry->username);
			if ($userEmail != null)
			{
				$this->logger->log("User ".$logEntry->username." was blocked, sending unblock instructions", JLog::DEBUG);
				$config = JFactory::getConfig();
				$siteName = $config->getValue('config.sitename' );
				$this->notifier->sendMail(
					JText::sprintf('BLOCKED_SUBJECT',
						$siteName),
					JText::sprintf('BLOCKED_BODY',
						$siteName,
						$this->getUnblockLink($id)
					),
					$userEmail);
			} else {
				$this->logger->log("Unknown user (".$logEntry->username.") blocked, not sending any notifications", JLog::DEBUG);
			}
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


	function getIPAddr()
	{
		return getenv('REMOTE_ADDR');
	}
	
	private function init()
	{
		$this->logger = new BFStopLogger((bool)$this->params->get('loggingEnabled'));
		$this->db  = new BFStopDBHelper($this->logger);
		$this->notifier = new BFStopNotifier($this->logger, $this->db,
			(int)$this->params->get( 'emailtype' ),
			$this->params->get('emailaddress'),
			$this->params->get('userIDs'));
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

		$this->logger->log('Failed login attempt from IP address '.$logEntry->ipaddress, JLog::DEBUG);
	
		// insert into log:
		$this->db->insertFailedLogin($logEntry);

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
		$maxNumber = (int)$this->params->get('notifyFailedNumber');
		$this->notifier->failedLogin($logEntry, $maxNumber);
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
		$this->logger->log('Successful login by '.$logEntry->username.' from IP address '.$logEntry->ipaddress, JLog::DEBUG);
	
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
			$this->logger->log("Blocked IP Address $ipaddress tried to access ".
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

