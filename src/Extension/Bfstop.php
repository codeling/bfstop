<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Extension;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\ApiHelper;
use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Codeling\Plugin\System\Bfstop\Helper\HtaccessHelper;
use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use Codeling\Plugin\System\Bfstop\Helper\NotifierHelper;
use Codeling\Plugin\System\Bfstop\Helper\RiskHelper;
use Codeling\Plugin\System\Bfstop\Helper\TokenHelper;
use Codeling\Plugin\System\Bfstop\Helper\UsernameHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Uri\Uri;
use Joomla\Event\SubscriberInterface;

class Bfstop extends CMSPlugin implements SubscriberInterface
{
	protected $autoloadLanguage = true;

	// values of the "notifyBlockedUser" setting besides 0 (off) and 1 (only to
	// users who logged in from the blocked address before)
	private const NotifyBlockedAnyAddress = 2;

	// the bits of the "enabledForOrigin" setting: the parts of Joomla the
	// plugin is active for, each the application's client id + 1
	public const OriginFrontend = 1;
	public const OriginBackend = 2;
	public const OriginApi = 4;

	/**
	 * What the settings are while they have not been saved: the same as the
	 * settings page shows for them (com_bfstop's forms/settings.xml - a test
	 * compares them). The plugin is enabled by the installation, so it runs
	 * with these until an administrator opens the settings.
	 */
	/**
	 * Values the plugin keeps among its settings for itself: they are not on
	 * the settings page, so saving that page must keep them (see com_bfstop's
	 * SettingsModel).
	 */
	public const InternalSettings = array('addressesCanonical', 'lastPurge');

	public const DefaultSettings = array(
		'blockNumber' => 10,
		'checkInterval' => 10080,
		'maxBlocksBefore' => 3,
		'notifyUsePasswordReminder' => 1,
		'adaptiveDelayMax' => 0,
		'adaptiveDelayThresholdMin' => 50,
		'adaptiveDelayThresholdMax' => 200,
		// failed logins are purged after this many weeks unless the
		// administrator chose another time (0 = never). Keeping them for ever
		// is not needed to protect anything, and they are personal data
		// (addresses, usernames)
		'deleteOld' => 4,
		'logLevel' => 8, // Log::ERROR
		'riskCommonUsernames' => "admin\nadministrator\nroot\ntest\nwebmaster",
		// frontend, backend and the Web Services API
		'enabledForOrigin' => self::OriginFrontend | self::OriginBackend | self::OriginApi,
	);

	private LoggerHelper $logger;
	private NotifierHelper $notifier;
	private DatabaseHelper $mydb;
	// the client's actual address while handling a failed login; the failed
	// login entry holds the key it is tracked under instead (IPv6: its network)
	private ?string $clientAddress = null;

	public static function getSubscribedEvents(): array
	{
		return array(
			'onUserLoginFailure' => 'onUserLoginFailure',
			'onUserLogin'        => 'onUserLogin',
			'onAfterInitialise'  => 'onAfterInitialise',
			'onAfterRoute'       => 'onAfterRoute',
			'onAfterApiRoute'    => 'onAfterApiRoute',
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

	/**
	 * A request parameter as a string: "option[]=x" and the like give arrays,
	 * which strcmp() and friends don't take (a TypeError on PHP 8, i.e. an
	 * error page instead of the intended answer). Such a value is returned as
	 * a NUL character: not empty - so it doesn't pass for "parameter not
	 * given" - and not equal to anything the parameter can legitimately be.
	 */
	private function requestString($name, $filter = 'cmd')
	{
		$value = $this->getApplication()->getInput()->get($name, '', $filter);
		return is_string($value) ? $value : "\0";
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

	private function getUnblockLink($id, $username)
	{
		$token = $this->mydb->getNewUnblockToken($id,
			TokenHelper::getToken($this->logger), $username);
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
		if ($this->getStringParam('blockMode', 'full') === 'off')
		{
			return;
		}
		// if the IP address is blocked we actually shouldn't be here in
		// the first place I guess, but just to make sure
		if ($this->mydb->isIPBlocked($this->clientAddress ?? $logEntry->ipaddress))
		{
			$this->logger->log('IP '.$logEntry->ipaddress.
				' is already blocked!', Log::ERROR);
			return;
		}
		$maxBlocksBefore = $this->getIntParam('maxBlocksBefore', self::DefaultSettings['maxBlocksBefore']);
		$progressiveEnabled = $this->getBoolParam('progressiveBlockDuration', false);
		if ($maxBlocksBefore > 0 || $progressiveEnabled)
		{
			$numberOfPrevBlocks = $this->mydb->
				getNumberOfPreviousBlocks($logEntry->ipaddress);
			$this->logger->log('Number of previous blocks for IP='.
				$logEntry->ipaddress.': '.$numberOfPrevBlocks,
				Log::DEBUG);
			if ($maxBlocksBefore > 0 && $numberOfPrevBlocks >= $maxBlocksBefore)
			{
				$this->logger->log('Number of previous blocks '.
					'exceeds configured maximum, blocking '.
					'permanently!', Log::INFO);
				$duration = 0;
			}
			elseif ($progressiveEnabled && $duration > 0 && $numberOfPrevBlocks > 0)
			{
				// doubles the block duration per repeat offense, capped at
				// 2^6=64x, mirroring OWASP's doubling-lockout-duration
				// recommendation
				$multiplier = 2 ** min($numberOfPrevBlocks, 6);
				$newDuration = $duration * $multiplier;
				$this->logger->log('Progressive block duration: '.
					$numberOfPrevBlocks.' previous block(s), scaling '.
					'duration '.$duration.' by '.$multiplier.'x to '.
					$newDuration, Log::INFO);
				$duration = $newDuration;
			}
		}
		$usehtaccess = $this->getStringParam('blockMode', 'full') === 'htaccess';
		$htaccessPath = $this->getHtaccessPath();
		if ($usehtaccess)
		{
			// the file only holds what is still blocked
			$this->removeLiftedHtaccessBlocks();
		}
		// has to be found out before blocking, which marks these failed logins
		// as handled
		$targetedOtherAccounts = $this->getBoolParam('notifyBlockedUser', false) &&
			$this->mydb->hasFailedLoginsForOtherAccounts(
				$this->getRealDurationFromDBDuration($this->getIntParam('checkInterval', self::DefaultSettings['checkInterval'])),
				$logEntry->ipaddress, $logEntry->username, $logEntry->logtime);
		$id = $this->mydb->blockIP($logEntry, $duration, $usehtaccess, $htaccessPath);
		if ($id < 1)
		{
			// nothing is blocked: neither tell the administrators that
			// something was, nor mail an unblock link for a block which
			// doesn't exist
			$this->logger->log('Could not block IP address '.$logEntry->ipaddress.
				', see the previous errors', Log::ERROR);
			return;
		}

		$this->logger->log('Inserted IP address '.$logEntry->ipaddress.
			' into block list', Log::INFO);
		// send email notification to admin
		$this->notifier->blockedNotifyAdmin($logEntry,
			$this->getRealDurationFromDBDuration($duration),
			$this->getIntParam('notifyBlockedNumber', 5));
		if ($this->getBoolParam('notifyBlockedUser', false))
		{
			$userEmail = $this->mydb->getUserEmailByName($logEntry->username);
			if ($userEmail != null && $targetedOtherAccounts)
			{
				// The link unblocks this IP address, and it goes to the owner
				// of the account of the last failed login. If the attempts
				// which got the address blocked also went against other
				// accounts, whoever caused that could just as well own this
				// account - and would get to continue with the other
				// accounts by following the link.
				$this->logger->log("Existing user '".
					$logEntry->username."' was blocked, but the failed ".
					"logins from this address also targeted other accounts - ".
					"not sending unblock instructions",
					Log::INFO);
			}
			elseif ($userEmail != null && ($withheld = $this->whyNoUnblockMail($logEntry)) !== null)
			{
				$this->logger->log("Existing user '".$logEntry->username.
					"' was blocked, but ".$withheld." - not sending unblock instructions",
					Log::INFO);
			}
			elseif ($userEmail != null)
			{
				$this->logger->log("Existing user '".
					$logEntry->username.
					"' was blocked, sending unblock ".
					"instructions",
					Log::INFO);
				$this->notifier->sendUnblockMail($userEmail,
					$this->getUnblockLink($id, $logEntry->username));
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

	/**
	 * Anybody can make the plugin send an unblock email to a user: by failing
	 * to log in with that username from an IP address until it is blocked.
	 * To keep that from being used to flood somebody's inbox:
	 *
	 * - by default (mode 1) the email is only sent if the user has logged in
	 *   from the blocked IP address before - which is where somebody
	 *   locking themselves out comes from, but never an attacker's address;
	 * - if it is to go to any address (mode 2), at most one email which can
	 *   still be used is out for a user at any time.
	 *
	 * @return string|null why no email is sent, null if it may be
	 */
	private function whyNoUnblockMail($logEntry)
	{
		if ($this->getIntParam('notifyBlockedUser', 0) === self::NotifyBlockedAnyAddress)
		{
			return $this->mydb->hasCurrentUnblockToken($logEntry->username)
				? 'there already is an unblock link for this user which can be used'
				: null;
		}
		return $this->mydb->hasLoggedInFrom($this->clientAddress ?? $logEntry->ipaddress,
			$logEntry->username, $this->getIntParam('ipv6PrefixLength', 64))
			? null
			: 'the user has never logged in from this IP address';
	}

	private function getHtaccessPath()
	{
		$htaccessPath = $this->getStringParam('htaccessPath', JPATH_ROOT);
		if ($htaccessPath === "")
		{
			$this->logger->log('htaccessPath empty, setting it to '.JPATH_ROOT, Log::INFO);
			$htaccessPath = JPATH_ROOT;
		}
		return $htaccessPath;
	}

	/**
	 * With blocking through .htaccess the web server holds back a blocked
	 * address; it doesn't know that a block has run out or was lifted, see
	 * HtaccessHelper::removeLiftedBlocks().
	 */
	private function removeLiftedHtaccessBlocks()
	{
		(new HtaccessHelper($this->getHtaccessPath(), $this->logger))->removeLiftedBlocks($this->mydb);
	}

	private function getRealDurationFromDBDuration($duration)
	{
		return ($duration <= 0)
			? DatabaseHelper::$UNLIMITED_DURATION
			: $duration;
	}

	/**
	 * The number of failed attempts allowed from a single IP before it gets
	 * blocked, adjusted by the per-attempt risk score (issue #76): a
	 * trusted-looking attempt (negative score) gets a higher threshold, a
	 * suspicious-looking one (positive score) a lower one. Floored at
	 * riskMinBlockNumber so an extreme score can never reduce this to
	 * 0-or-below and effectively instant-block a legitimate user.
	 */
	private function determineEffectiveBlockNumber($riskScore)
	{
		$blockNumber = $this->getIntParam('blockNumber', self::DefaultSettings['blockNumber']);
		$reductionPerPoint = $this->getIntParam('riskBlockNumberReductionPerPoint', 1);
		$minBlockNumber = $this->getIntParam('riskMinBlockNumber', 2);
		$effective = (int) round($blockNumber - $riskScore * $reductionPerPoint);
		return max($minBlockNumber, $effective);
	}

	private function blockIfTooManyAttempts($logEntry, $riskScore = 0)
	{
		$blockInterval = $this->getIntParam('blockDuration', NotifierHelper::$ONE_DAY);
		$maxNumber = $this->determineEffectiveBlockNumber($riskScore);
		$checkInterval = $this->getRealDurationFromDBDuration(
			$this->getIntParam('checkInterval', self::DefaultSettings['checkInterval']));
		if ($this->mydb->getNumberOfFailedLogins(
			$checkInterval,
			$logEntry->ipaddress,
			$logEntry->logtime) < $maxNumber)
		{
			return;
		}
		$this->block($logEntry, $blockInterval);
	}

	/**
	 * Account-level throttle: once a username has accumulated enough failed
	 * attempts *from any source IP combined* within the configured window,
	 * every further failed attempt for that username gets an extra forced
	 * delay. Unlike blockIfTooManyAttempts() (which is scoped to a single
	 * IP), this catches an attacker who distributes attempts against one
	 * target account across many different IPs - a distributed attack no
	 * per-IP threshold can ever detect on its own. The account itself is
	 * never locked - only wrong attempts get progressively expensive, so a
	 * correct password still logs the real owner in immediately.
	 *
	 * @return int the seconds to delay the response by
	 */
	private function accountThrottleDelay($logEntry)
	{
		if (!$this->getBoolParam('accountThrottleEnabled', true))
		{
			return 0;
		}
		$checkInterval = $this->getIntParam('accountCheckInterval', 60);
		$accountBlockNumber = $this->getIntParam('accountBlockNumber', 20);
		$numberOfFailedLogins = $this->mydb->getNumberOfFailedLoginsForUsername(
			$checkInterval, $logEntry->username, $logEntry->logtime);
		if ($numberOfFailedLogins < $accountBlockNumber)
		{
			return 0;
		}
		$throttleDelay = max(0, $this->getIntParam('accountThrottleDelay', 5));
		if ($throttleDelay > 0)
		{
			$this->logger->log('Account-level throttle triggered for username \''.
				$logEntry->username.'\' ('.$numberOfFailedLogins.
				' failed attempts across all IPs within '.$checkInterval.
				' minutes), adding '.$throttleDelay.'s delay', Log::INFO);
		}
		return $throttleDelay;
	}

	private function init()
	{
		$this->logger = new LoggerHelper($this->getIntParam('logLevel', self::DefaultSettings['logLevel']),
			LoggerHelper::maxBytesFromMegabytes($this->getIntParam('logMaxSize', LoggerHelper::DefaultMaxSizeMB)));
		$this->mydb = new DatabaseHelper($this->logger);
		$this->notifier = new NotifierHelper($this->logger, $this->mydb,
			$this->params->get('emailaddress', ''),
			$this->getIntParam('userID', -1),
			$this->getIntParam('userGroup', -1),
			$this->getBoolParam('groupNotificationEnabled', false));
	}

	private function notifyOfRemainingAttempts($logEntry, $riskScore = 0)
	{
		// remaining attempts notification only makes sense if we
		// actually block
		$notifyRemaining = $this->getBoolParam('notifyRemainingAttempts', false);
		$passwordReminder = $this->getIntParam('notifyUsePasswordReminder', self::DefaultSettings['notifyUsePasswordReminder']);
		if ($this->getStringParam('blockMode', 'full') === 'off' ||
			(!$notifyRemaining &&
			  !($passwordReminder == -1 || $passwordReminder > 0)) ||
			// an API client gets no messages shown
			$this->isApiRequest())
		{
			// avoid database access if reminders are disabled anyway
			return;
		}
		$allowedAttempts = $this->determineEffectiveBlockNumber($riskScore);
		$checkInterval = $this->getRealDurationFromDBDuration(
			$this->getIntParam('checkInterval', self::DefaultSettings['checkInterval']));
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
		$enabledFor = $this->getIntParam('enabledForOrigin', self::DefaultSettings['enabledForOrigin']);
		// site 0, administrator 1, api 3: see the Origin* constants
		return (($enabledFor & ($this->getApplication()->getClientId() + 1)) != 0);
	}

	private function isApiRequest()
	{
		return $this->getApplication()->isClient('api');
	}

	/**
	 * The global-attack-volume-based delay (unchanged), plus an additional
	 * delay proportional to the per-attempt risk score (issue #76) - the two
	 * are independent, orthogonal mechanisms; only a positive (suspicious)
	 * score adds delay, a trust bonus never reduces it below the base.
	 */
	private function determineDelayDuration($riskScore = 0)
	{
		$baseDelay = $this->determineBaseDelayDuration();
		$riskDelaySecondsPerPoint = $this->getIntParam('riskDelaySecondsPerPoint', 2);
		return $baseDelay + max(0, $riskScore) * $riskDelaySecondsPerPoint;
	}

	private function determineBaseDelayDuration()
	{
		$delayDuration = $this->getIntParam('delayDuration', 0);
		$adaptive = $this->getBoolParam('adaptiveDelay', false);
		if ($adaptive)
		{
			$maxDelay = $this->getIntParam('adaptiveDelayMax', self::DefaultSettings['adaptiveDelayMax']);
			$lowThreshold = $this->getIntParam('adaptiveDelayThresholdMin', self::DefaultSettings['adaptiveDelayThresholdMin']);
			$highThreshold = $this->getIntParam('adaptiveDelayThresholdMax', self::DefaultSettings['adaptiveDelayThresholdMax']);
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

	private function trackedAddress($ipAddress)
	{
		return IpHelper::trackedAddress($ipAddress, $this->getIntParam('ipv6PrefixLength', 64));
	}

	/**
	 * The form in which the username of a failed login is stored, mailed and
	 * logged, see UsernameHelper.
	 */
	private function usernameForStorage($username)
	{
		$mode = $this->getStringParam('unknownUsernameMode', UsernameHelper::ModeHash);
		$isReadable = ($mode !== UsernameHelper::ModePlain) &&
			($this->mydb->accountExists($username) ||
				RiskHelper::isCommonUsername($this->params, $username));
		return UsernameHelper::forStorage($username, $mode, $isReadable,
			$this->getApplication()->get('secret', ''));
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
		$username = (string) ($user['username'] ?? '');
		if ($this->isApiRequest() && $username === '')
		{
			// Joomla tries to log in every API request to an endpoint which
			// isn't public, also one which comes without any credentials:
			// that isn't an attempt to guess any. The authentication plugins
			// don't pass on the username they were given, see ApiHelper
			$username = ApiHelper::requestCredentialsUsername();
			if ($username === null)
			{
				$this->logger->log('Ignoring failed login of an API request without credentials from '.
					$ipAddress, Log::DEBUG);
				return;
			}
		}
		$username = mb_strimwidth($username, 0, 150, "...");
		$riskScore = RiskHelper::computeScore($this->mydb, $this->logger, $this->params, $ipAddress, $username);

		$logEntry = new \stdClass();
		$logEntry->id = null;
		$this->clientAddress = $ipAddress;
		$logEntry->ipaddress = $this->trackedAddress($ipAddress);
		$logEntry->logtime = date("Y-m-d H:i:s");
		$logEntry->username = $this->usernameForStorage($username);
		$logEntry->origin = $this->getApplication()->getClientId();

		$this->logger->log('Failed login attempt from IP address '.
			$logEntry->ipaddress, Log::DEBUG);

		// Everything is recorded and evaluated *before* the delay below. The
		// password has been checked by now, so the delay only holds back the
		// response; if the attempt was only counted after the sleep, a burst
		// of parallel requests would all run before the first of them
		// reached the block threshold, and each of them would tie up a
		// worker for the whole delay.
		$this->mydb->insertFailedLogin($logEntry);

		$this->notifyOfRemainingAttempts($logEntry, $riskScore);

		// $username is what was typed; the entry only holds a hash of it if
		// it isn't an account (see usernameForStorage())
		if ($this->getBoolParam('notifyFailedOnlyExisting', false) &&
			!$this->mydb->accountExists($username))
		{
			$this->logger->log('Not notifying of failed login: the username does not belong to an account', Log::DEBUG);
		}
		else
		{
			$maxNumber = $this->getIntParam('notifyFailedNumber', 0);
			$this->notifier->failedLogin($logEntry, $maxNumber);
		}
		$this->blockIfTooManyAttempts($logEntry, $riskScore);

		$delayDuration = $this->accountThrottleDelay($logEntry) + $this->determineDelayDuration($riskScore);
		if ($delayDuration > 0)
		{
			// a blocked address gets nothing more out of a slow response;
			// don't let it hold on to a worker (attackers could otherwise use
			// the delay to exhaust the server's workers)
			if ($this->mydb->isIPBlocked($ipAddress))
			{
				$this->logger->log('Not delaying the response, IP address '.
					$ipAddress.' is blocked', Log::DEBUG);
			}
			else
			{
				$seconds = self::cappedDelay($delayDuration);
				if ($seconds < (int) round($delayDuration))
				{
					$this->logger->log('Delay of '.round($delayDuration).'s cut to '.
						$seconds.'s', Log::WARNING);
				}
				sleep($seconds);
			}
		}
	}

	/**
	 * Every second of delay occupies a PHP worker, which is what an attacker
	 * with many addresses would like to run out of - so however the delays of
	 * the settings add up, one response is never held back longer than this.
	 */
	public const MaxDelaySeconds = 60;

	public static function cappedDelay($seconds)
	{
		return max(0, min((int) round($seconds), self::MaxDelaySeconds));
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
		$info->username = (string) ($user['username'] ?? '');
		$this->logger->log('Successful login by '.$info->username.
			' from IP address '.$info->ipaddress, Log::DEBUG);
		$this->mydb->successfulLogin($info, $this->trackedAddress($info->ipaddress));
	}

	/**
	 * A blocked IP may only reach com_bfstop's unblock page, and only with an
	 * unexpired token that was issued for one of *its own* blocks. The pass
	 * has to stay this narrow: the request is the one that consumes the token,
	 * so it must really be the unblock view (no task, no other component).
	 * Letting any request with view=tokenunblock through would turn a single
	 * valid token - which the owner of any account can get emailed by getting
	 * themselves blocked - into a reusable key around the block for logins
	 * (e.g. option=com_users&task=user.login&view=tokenunblock&token=...).
	 */
	private function isUnblockRequest($blockIds)
	{
		// tokenunblock is a view of the site; in the backend, the request of
		// a guest would go to com_login (see requestedOption())
		if (!$this->getApplication()->isClient('site') ||
			strcmp($this->requestString('option'), 'com_bfstop') != 0 ||
			strcmp($this->requestString('view'), 'tokenunblock') != 0 ||
			$this->requestString('task') !== '')
		{
			return false;
		}
		$token = $this->requestString('token', 'string');
		$result = $this->mydb->unblockTokenValidForBlocks($token, $blockIds);
		if ($result)
		{
			// deliberately not logging the token: it is a bearer secret and
			// the log is readable in the backend
			$this->logger->log('Seeing a valid unblock token for this IP '.
				'address, letting the request pass through to com_bfstop',
				Log::INFO);
		}
		return $result;
	}

	/**
	 * The controller and the method of it which Joomla's component dispatcher
	 * runs for this request, in lower case, as it determines them
	 * (ComponentDispatcher::dispatch(), BaseController::execute()): "task" is
	 * either "controller.method" - anything after a second dot is ignored - or
	 * just the method, with the controller from the "controller" parameter;
	 * the method's case doesn't matter. Both are '' if there is no task (which
	 * shows a view). Checks of the task have to go by this, not by the raw
	 * parameter, or "task=user.LOGIN" or "task=user.login.x" would not be
	 * recognised as the login they are.
	 *
	 * @return string[] array(controller, method)
	 */
	private function requestedTask()
	{
		$task = strtolower($this->requestString('task'));
		if ($task === '')
		{
			return array('', '');
		}
		if (strpos($task, '.') !== false)
		{
			$parts = explode('.', $task);
			return array($parts[0], $parts[1]);
		}
		$controller = strtolower($this->requestString('controller'));
		return array($controller === '' ? 'display' : $controller, $task);
	}

	// the components the backend runs for a guest (or a user who may not log in
	// there) as requested; every other request goes to com_login, see
	// AdministratorApplication::$allowedUnprivilegedOptions
	private const UnprivilegedBackendOptions = array('com_login', 'com_ajax');

	/**
	 * The component Joomla runs for this request, in lower case. Usually the
	 * "option" parameter, but not in the backend: there,
	 * AdministratorApplication::findOption() - called when the request is
	 * dispatched, after onAfterRoute - runs com_login for a guest, whatever
	 * else the request names, and com_cpanel if it names nothing. Checks of
	 * the component have to go by that, or a login posted to the backend
	 * with "option" left out (or set to any other component) would not be
	 * recognised as the login it is.
	 */
	private function requestedOption()
	{
		$option = strtolower($this->requestString('option'));
		$app = $this->getApplication();
		if (!$app->isClient('administrator'))
		{
			return $option;
		}
		$user = $app->getIdentity();
		if (($user === null || $user->guest || !$user->authorise('core.login.admin')) &&
			!in_array($option, self::UnprivilegedBackendOptions, true))
		{
			return 'com_login';
		}
		return $option === '' ? 'com_cpanel' : $option;
	}

	// the tasks of com_users (controller.method) with which a user who forgot
	// their password or username gets a new one: the forms of the reset and
	// remind views post to them (index.php?task=reset.request, ...)
	private const PasswordRecoveryTasks = array(
		'reset.request',
		'reset.confirm',
		'reset.complete',
		'remind.remind',
		'user.remind',
	);

	/**
	 * Password reset / username reminder must stay reachable even for a
	 * blocked IP - otherwise a legitimate user who got blocked (and is told
	 * by this very plugin to use password reset, see
	 * notifyOfRemainingAttempts()) would have no way to actually act on
	 * that advice, turning the block itself into a denial-of-service
	 * against them (see OWASP Authentication Cheat Sheet guidance on
	 * lockouts).
	 *
	 * That is: showing the reset and remind views, and submitting their
	 * forms - nothing else. In particular not any task with view=reset: the
	 * task is what Joomla runs, the view is ignored then, so that would let a
	 * blocked IP log in (option=com_users&view=reset&task=user.login).
	 */
	private function isPasswordRecoveryRequest()
	{
		if ($this->requestedOption() !== 'com_users')
		{
			return false;
		}
		list($controller, $method) = $this->requestedTask();
		if ($method === '' || ($controller === 'display' && $method === 'display'))
		{
			$view = strtolower($this->requestString('view'));
			$result = ($view === 'reset' || $view === 'remind');
			$what = 'view '.$view;
		}
		else
		{
			$result = in_array($controller.'.'.$method, self::PasswordRecoveryTasks, true);
			$what = 'task '.$controller.'.'.$method;
		}
		if ($result)
		{
			$this->logger->log('Allowing blocked IP through to the '.
				'password recovery ('.$what.'), so a blocked '.
				'legitimate user can still recover their account',
				Log::INFO);
		}
		return $result;
	}

	/**
	 * Detects a request that actually submits login credentials, for
	 * "Login Only" block mode (issue #187): on the frontend, credentials
	 * are submitted to com_users (task=user.login), the backend login form
	 * posts to com_login (task=login) - merely viewing the login form (no
	 * task, or a display task) doesn't match, so it stays reachable.
	 *
	 * The task is compared as Joomla's dispatcher runs it (see
	 * requestedTask()): the login method of whatever controller, in any case
	 * - "task=user.LOGIN", "task=user.login.x" and
	 * "controller=user&task=login" are all logins. Matching more than
	 * Joomla would run only blocks a request which wouldn't do anything.
	 * The same goes for the component (see requestedOption()): a backend
	 * login without "option=com_login" is a login all the same.
	 */
	private function isLoginAttemptRequest()
	{
		if ($this->isApiRequest())
		{
			// an API request carries its credentials with it, each one with
			// them is a login (see ApiHelper)
			return ApiHelper::requestCredentialsUsername() !== null;
		}
		$option = $this->requestedOption();
		list(, $method) = $this->requestedTask();
		$result = ($option === 'com_users' || $option === 'com_login') && $method === 'login';
		if ($result)
		{
			$this->logger->log('Detected a login-attempt request (task='.
				$this->requestString('task').')', Log::DEBUG);
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
		// lookups of the block and allow list need the addresses in canonical
		// form, which entries of earlier versions are not in: once, before the
		// first lookup of this version (every request has one, later). The
		// installer script can't do this reliably - the class of the previous
		// version may be loaded still
		if (!$this->getBoolParam('addressesCanonical', false))
		{
			$this->canonicalizeStoredAddressesOnce();
		}
		// periodic maintenance, at most once a day
		$purgeInterval = 86400; // = 24*60*60 => one day
		$lastPurge = $this->params->get('lastPurge', 0);
		$now = time();
		if ($now > ($lastPurge + $purgeInterval))
		{
			$purgeAge = $this->getIntParam('deleteOld', self::DefaultSettings['deleteOld']);
			if ($purgeAge > 0)
			{
				$this->mydb->purgeOldEntries($purgeAge);
			}
			// regardless of the purge age setting: these are not deleted by age
			$this->mydb->trimFailedLogins();
			$this->mydb->trimUsernameStats();
			$this->mydb->pruneKnownIps();
			$this->mydb->pruneDnsCache();
			$this->mydb->purgeExpiredUnblockTokens();
			if ($this->getStringParam('blockMode', 'full') === 'htaccess')
			{
				$this->removeLiftedHtaccessBlocks();
			}
			LoggerHelper::pruneByAge($this->getIntParam('logKeepDays', LoggerHelper::DefaultKeepDays));
			$this->params->set('lastPurge', $now);
			$this->mydb->saveLastPurge($now);
		}
	}

	/**
	 * Brings the stored addresses into canonical form, if no other request
	 * did or does: every request starts out with the settings as they were
	 * when it began, so after the update all requests arriving before the
	 * first of them is done would see the setting unset, and each would go
	 * through the whole block and allow list (and update the same rows) - on
	 * a busy site with a long list, many at once. The first takes a lock; the
	 * others go on without waiting (their lookups may miss an entry which
	 * isn't converted yet, as they would have before the update). Once it has
	 * the lock, a request checks the stored setting again, as another one may
	 * have finished in the meantime. If no lock can be taken (no writable
	 * temporary directory), it is done without one: it can be run more than
	 * once, it only costs time.
	 */
	private function canonicalizeStoredAddressesOnce()
	{
		$lockFile = HtaccessHelper::lockDirectory().'/bfstop-canonicalize-'.
			md5((string) $this->getApplication()->get('db').(string) $this->getApplication()->get('dbprefix')).'.lock';
		$handle = @fopen($lockFile, 'c');
		if ($handle !== false && !flock($handle, LOCK_EX | LOCK_NB))
		{
			fclose($handle);
			$this->logger->log('Another request is converting the stored addresses, not waiting for it', Log::DEBUG);
			return;
		}
		try
		{
			if (!$this->mydb->getPluginSetting('addressesCanonical', false))
			{
				$changed = $this->mydb->canonicalizeStoredAddresses();
				$this->mydb->savePluginSetting('addressesCanonical', 1);
				$this->logger->log('Converted '.$changed.' stored address(es) to canonical form', Log::INFO);
			}
			$this->params->set('addressesCanonical', 1);
		}
		finally
		{
			if ($handle !== false)
			{
				flock($handle, LOCK_UN);
				fclose($handle);
			}
		}
	}

	/**
	 * The status code of the page shown to a blocked client, or null for none
	 * (which makes it 200). Set with http_response_code(), not as a raw
	 * "HTTP/1.x 403 ..." header: that would hard-code the protocol version,
	 * which is the web server's business (HTTP/2 doesn't even have a status line).
	 */
	public static function blockedResponseCode($useHttpError)
	{
		return $useHttpError ? 403 : null;
	}

	/**
	 * The headers of the page shown to a blocked client.
	 *
	 * It must never be cached: a cache (browser, proxy, CDN) which kept it
	 * would show it to other visitors of the same URL.
	 */
	public static function blockedResponseHeaders()
	{
		return array(
			'Cache-Control: no-store, no-cache, must-revalidate, private',
			'Pragma: no-cache',
		);
	}

	/**
	 * Enforcing the block happens after routing, not in onAfterInitialise:
	 * the exemptions below look at option/view/task, which with
	 * search-engine-friendly URLs (e.g. /index.php/component/users/reset)
	 * are only populated once the router has run.
	 */
	public function onAfterRoute($event)
	{
		$this->enforceBlock();
	}

	/**
	 * The Web Services API (api/index.php) doesn't trigger onAfterRoute, but
	 * this, before it logs in the request.
	 */
	public function onAfterApiRoute($event)
	{
		$this->enforceBlock();
	}

	private function enforceBlock()
	{
		if (!isset($this->mydb))
		{
			// onAfterInitialise did not run (or bailed out early)
			$this->init();
		}
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		$ipaddress = IpHelper::getAddress($this->logger);
		if ($this->mydb->isIPOnAllowList($ipaddress))
		{
			return;
		}
		$blockIds = $this->mydb->getActiveBlockIds($ipaddress);
		if (count($blockIds) > 0)
		{
			$this->logger->log("Blocked IP Address $ipaddress ".
				"trying to access ".
				$this->mydb->getClientString(
					$this->getApplication()->getClientId()),
				Log::INFO);
			// the unblock page and the password recovery are pages of the
			// site; the API has neither
			if (!$this->isApiRequest() && $this->isUnblockRequest($blockIds))
			{
				return;
			}
			if (!$this->isApiRequest() && $this->isPasswordRecoveryRequest())
			{
				return;
			}
			if ($this->getStringParam('blockMode', 'full') === 'loginonly' &&
				!$this->isLoginAttemptRequest())
			{
				// let the blocked IP keep browsing normally; only an
				// actual login attempt gets rejected below
				return;
			}
			$this->mydb->recordBlockedAttempt($blockIds);
			$status = self::blockedResponseCode($this->getBoolParam('useHttpError', true));
			if ($status !== null)
			{
				http_response_code($status);
			}
			foreach (self::blockedResponseHeaders() as $header)
			{
				header($header);
			}
			$message = $this->params->get('blockedMessage',
				Text::_('PLG_SYSTEM_BFSTOP_BLOCKED_IP_MESSAGE'));

			if ($this->getBoolParam('blockedMsgShowIP', false))
			{
				$message .= " ".Text::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_CLIENT_IP', $ipaddress);
			}
			if ($this->isApiRequest())
			{
				header('Content-Type: application/vnd.api+json; charset=utf-8');
				$message = self::blockedApiResponse($message, $status);
			}
			echo $message;
			$this->getApplication()->close();
		}
	}

	/**
	 * The body of the answer to a blocked API request: an error in the form
	 * the API answers others with (JSON:API, see Joomla's JsonapiRenderer).
	 */
	public static function blockedApiResponse($message, $status)
	{
		$error = array('title' => trim(html_entity_decode(strip_tags((string) $message), ENT_QUOTES | ENT_HTML5, 'UTF-8')));
		if ($status !== null)
		{
			$error['code'] = $status;
		}
		return json_encode(array('errors' => array($error)), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	}
}
