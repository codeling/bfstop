<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Extension;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\ApiHelper;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Codeling\Library\Bfstop\Helper\NotifierHelper;
use Codeling\Library\Bfstop\Helper\RiskHelper;
use Codeling\Library\Bfstop\Helper\TokenHelper;
use Codeling\Library\Bfstop\Helper\UsernameHelper;
use Codeling\Library\Bfstop\Origin;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\BlockPolicy;
use Codeling\Library\Bfstop\Service\BlockService;
use Codeling\Library\Bfstop\Service\DailyMaintenance;
use Codeling\Library\Bfstop\Service\LoginService;
use Codeling\Library\Bfstop\Settings;
use Codeling\Plugin\System\Bfstop\Service\LoginTurn;
use Codeling\Plugin\System\Bfstop\Service\RequestClassifier;
use Codeling\Plugin\System\Bfstop\Service\Responder;
use Joomla\CMS\Event\User\LoginEvent;
use Joomla\CMS\Event\User\LoginFailureEvent;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Event\SubscriberInterface;

/**
 * The plugin: what it does on Joomla's events. What to do about a failed
 * login and the maintenance are the library's (lib_bfstop, namespace
 * Codeling\Library\Bfstop): BlockPolicy, with BlockService and LoginService
 * doing what it decides, and DailyMaintenance. What a request is and what
 * the client is told are the plugin's own: RequestClassifier, Responder and
 * LoginTurn (Service namespace of the plugin). Its params are the settings
 * of BFStop, which are the component's (see services/provider.php and the
 * library's Settings): the plugin has none of its own.
 */
class Bfstop extends CMSPlugin implements SubscriberInterface
{
	// the language is loaded by init(), when the plugin handles an event (as
	// Joomla 6 does it): by the constructor, before the plugin has its
	// application, Joomla 5 would take it from Factory::getLanguage(), which
	// is deprecated
	protected $autoloadLanguage = false;
	private bool $languageLoaded = false;

	private LoggerHelper $logger;
	// created on first use (see notifier()): its constructor queries the
	// database, which most requests - none of them sends a mail - needn't pay for
	private ?NotifierHelper $notifier = null;
	// what isAccount() has found out in this event: login => bool
	private array $accounts = array();
	private Repositories $repositories;
	private LoginService $logins;
	private BlockService $blocker;
	private RequestClassifier $request;
	private BlockPolicy $policy;
	private Responder $responder;
	// kept for the whole request, unlike the others: the turn of a login
	// lasts from its routing to its login event
	private ?LoginTurn $loginTurn = null;
	// the client's actual address while handling a failed login; the failed
	// login entry holds the key it is tracked under instead (IPv6: its network)
	private ?string $clientAddress = null;

	public static function getSubscribedEvents(): array
	{
		// without the library (lib_bfstop, which the package installs first)
		// there is nothing the plugin could do: better none of its events
		// than a fatal error in every request
		if (!class_exists(Settings::class))
		{
			return array();
		}
		return array(
			'onUserLoginFailure' => 'onUserLoginFailure',
			'onUserLogin'        => 'onUserLogin',
			'onAfterInitialise'  => 'onAfterInitialise',
			'onAfterRoute'       => 'onAfterRoute',
			'onAfterApiRoute'    => 'onAfterApiRoute',
		);
	}

	private function intParam($paramName): int
	{
		return Settings::int($this->params, $paramName);
	}

	private function init()
	{
		if (!$this->languageLoaded)
		{
			$this->languageLoaded = $this->loadLanguage();
		}
		$app = $this->getApplication();
		$this->logger = LoggerHelper::fromSettings($this->params);
		$this->repositories = new Repositories($this->logger);
		$this->logins = new LoginService($this->repositories);
		$this->blocker = new BlockService($this->repositories);
		$this->request = new RequestClassifier($app);
		$this->policy = new BlockPolicy($this->params, $this->repositories, $this->logins, $this->logger);
		$this->responder = new Responder($app, $this->params, $this->logger);
		$this->loginTurn ??= new LoginTurn();
		$this->notifier = null;
		$this->accounts = array();
	}

	/**
	 * Whether $login is the username or email address of an account. Asked
	 * twice for the same login while a failed login is handled (to decide how
	 * to store it, and whether to notify of it): looked up once per event.
	 */
	private function isAccount($login): bool
	{
		return $this->accounts[$login] ??= $this->repositories->users()->accountExists($login);
	}

	private function notifier(): NotifierHelper
	{
		if ($this->notifier === null)
		{
			$this->notifier = new NotifierHelper($this->logger, $this->repositories,
				Settings::get($this->params, 'emailaddress'),
				$this->intParam('userID'),
				$this->intParam('userGroup'),
				Settings::bool($this->params, 'groupNotificationEnabled'));
		}
		return $this->notifier;
	}

	private function isEnabledForCurrentOrigin()
	{
		return Origin::isEnabled(Settings::get($this->params, 'enabledForOrigin'),
			$this->getApplication());
	}

	private function trackedAddress($ipAddress)
	{
		return IpHelper::trackedAddress($ipAddress, $this->intParam('ipv6PrefixLength'));
	}

	/**
	 * The form in which the username of a failed login is stored, mailed and
	 * logged, see UsernameHelper.
	 */
	private function usernameForStorage($username)
	{
		$mode = Settings::string($this->params, 'unknownUsernameMode');
		$isReadable = ($mode !== UsernameHelper::ModePlain) &&
			($this->isAccount($username) ||
				RiskHelper::isCommonUsername($this->params, $username));
		return UsernameHelper::forStorage($username, $mode, $isReadable,
			$this->getApplication()->get('secret', ''));
	}

	public function onUserLoginFailure(LoginFailureEvent $event)
	{
		$user = $event->getAuthenticationResponse();
		$this->init();
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		$ipAddress = IpHelper::getAddress($this->logger);
		if ($ipAddress === '')
		{
			$this->logger->log('Empty IP address!', Log::ERROR);
			return;
		}
		if ($this->repositories->allowList()->contains($ipAddress))
		{
			$this->logger->log('Ignoring failed login by allowed address '.$ipAddress, Log::INFO);
			return;
		}
		$username = (string) ($user['username'] ?? '');
		if ($this->request->isApi() && $username === '')
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
		$this->logins->recordFailedLogin($logEntry);

		// after recording it: a signal of the score may take time (the
		// reverse DNS lookup), and parallel requests waiting for it must
		// already count
		$riskScore = RiskHelper::computeScore($this->repositories, $this->logger, $this->params, $ipAddress, $username,
			$logEntry->ipaddress);

		// counted once (a query) for the message of the remaining attempts and
		// the decision to block; neither is made without blocking
		if (!$this->policy->isOff())
		{
			$attemptsLeft = $this->policy->attemptsLeft($logEntry, $riskScore);
			if ($this->responder->showsRemainingAttempts())
			{
				$this->responder->showRemainingAttempts($attemptsLeft);
			}
			if ($attemptsLeft <= 0)
			{
				$this->block($logEntry);
			}
		}
		// counted, and blocked if that was one too many: the next login of
		// this address may be handled (see LoginTurn). The mail below and the
		// delay take time it needn't wait for
		$this->loginTurn->end();

		// $username is what was typed; the entry only holds a hash of it if
		// it isn't an account (see usernameForStorage())
		if (Settings::bool($this->params, 'notifyFailedOnlyExisting') &&
			!$this->isAccount($username))
		{
			$this->logger->log('Not notifying of failed login: the username does not belong to an account', Log::DEBUG);
		}
		else
		{
			$this->notifier()->failedLogin($logEntry, $this->intParam('notifyFailedNumber'));
		}

		$delay = $this->policy->delaySeconds($logEntry, $riskScore);
		if ($delay > 0)
		{
			// a blocked address gets nothing more out of a slow response;
			// don't let it hold on to a worker (attackers could otherwise use
			// the delay to exhaust the server's workers)
			if ($this->repositories->blocks()->isBlocked($ipAddress))
			{
				$this->logger->log('Not delaying the response, IP address '.
					$ipAddress.' is blocked', Log::DEBUG);
			}
			else
			{
				$this->responder->delay($delay);
			}
		}
	}

	/**
	 * Blocks the client of $logEntry, if it isn't yet; the decision and the
	 * new block happen under a lock per tracked address (see
	 * BlockService::withLock()), the mails after it.
	 */
	private function block($logEntry)
	{
		$block = $this->blocker->withLock($logEntry->ipaddress, function () use ($logEntry)
		{
			return $this->blocker->blockAsDecided($logEntry, $this->clientAddress, $this->policy);
		});
		// the next login of this address sees the block (or the failed logins
		// counted) now: it needn't wait for the mails, see LoginTurn
		$this->loginTurn->end();
		if ($block !== null)
		{
			$this->notifyOfBlock($logEntry, $block['id'], $block['duration'], $block['targetedOtherAccounts']);
		}
	}

	/**
	 * The mails about the new block $id (after the lock: sending may take a
	 * while).
	 */
	private function notifyOfBlock($logEntry, $id, $duration, $targetedOtherAccounts)
	{
		$this->notifier()->blockedNotifyAdmin($logEntry, BlockPolicy::realDuration($duration),
			$this->intParam('notifyBlockedNumber'));
		if (!$this->policy->notifiesBlockedUser())
		{
			return;
		}
		// the failed login may have been typed with the email address, or in
		// another case: matched as Joomla matches a login (and accountExists())
		$account = $this->repositories->users()->accountByLogin($logEntry->username);
		if ($account === null)
		{
			$this->logger->log('Unknown user ('.$logEntry->username.') blocked, not sending any notifications', Log::DEBUG);
			return;
		}
		$userEmail = $account['email'];
		$withheld = $this->policy->whyNoUnblockMail($logEntry, $this->clientAddress, $targetedOtherAccounts,
			$account['username']);
		if ($withheld !== null)
		{
			$this->logger->log("Existing user '".$logEntry->username."' was blocked, but ".$withheld.
				' - not sending unblock instructions', Log::INFO);
			return;
		}
		try
		{
			$token = TokenHelper::getToken();
		}
		catch (\Throwable $e)
		{
			// no source of randomness: no link rather than a weak one
			$this->logger->log('Could not make an unblock token: '.$e->getMessage(), Log::ERROR);
			return;
		}
		if ($this->repositories->unblockTokens()->add($id, $token, $account['username']) === null)
		{
			// a link whose token isn't stored would lead nowhere
			$this->logger->log("Existing user '".$logEntry->username."' was blocked, but the unblock token ".
				'could not be stored - not sending unblock instructions', Log::ERROR);
			return;
		}
		$this->logger->log("Existing user '".$logEntry->username."' was blocked, sending unblock instructions", Log::INFO);
		$this->notifier()->sendUnblockMail($userEmail, TokenHelper::unblockLink($token));
	}

	public function onUserLogin(LoginEvent $event)
	{
		$user = $event->getAuthenticationResponse();
		// nothing to count: the next login of this address may be handled
		$this->loginTurn?->end();
		$this->init();
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		$ipAddress = IpHelper::getAddress($this->logger);
		if ($ipAddress === '')
		{
			// no address to remember as a known one (and none to tell that
			// the login is from a known one)
			$this->logger->log('Empty IP address!', Log::ERROR);
			return;
		}
		$info = new \stdClass();
		$info->ipaddress = $ipAddress;
		$info->username = (string) ($user['username'] ?? '');
		// failed logins may have been typed with the email address
		$info->email = (string) ($user['email'] ?? '');
		$this->logger->log('Successful login by '.$info->username.
			' from IP address '.$info->ipaddress, Log::DEBUG);
		$this->logins->recordSuccessfulLogin($info, $this->trackedAddress($info->ipaddress),
			IpHelper::trackedAddress($info->ipaddress, IpHelper::trustPrefixLength(
				$this->intParam('ipv6PrefixLength'))));
	}

	public function onAfterInitialise($event)
	{
		$this->init();
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		// the daily maintenance is the task of Joomla's Task Scheduler (plugin
		// plg_task_bfstop); only if it didn't run for two days - the site doesn't
		// use the scheduler, or the task is gone - a request does it, which costs
		// no query as long as it did (see MaintenanceSchedule)
		(new DailyMaintenance($this->repositories, $this->params))->runIfOverdue();
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
		if (!isset($this->repositories))
		{
			// onAfterInitialise did not run (or bailed out early)
			$this->init();
		}
		if (!$this->isEnabledForCurrentOrigin())
		{
			return;
		}
		$ipaddress = IpHelper::getAddress($this->logger);
		if ($this->repositories->allowList()->contains($ipaddress))
		{
			return;
		}
		$blockIds = $this->repositories->blocks()->activeIdsFor($ipaddress);
		if ($blockIds !== null && count($blockIds) === 0 && !$this->policy->isOff() &&
			$this->request->isPasswordLogin() &&
			$this->loginTurn->await($this->trackedAddress($ipaddress), $ipaddress, $this->logger))
		{
			// the logins before this one may have got the address blocked
			$blockIds = $this->repositories->blocks()->activeIdsFor($ipaddress);
		}
		if ($blockIds === null)
		{
			// the block list can't be read (see the previous error): browsing
			// goes on, but a login attempt - the one thing the block is there
			// to stop - is refused rather than let through unchecked
			$loginAttempt = $this->request->isLoginAttempt();
			$this->logger->log('Could not find out whether '.$ipaddress.' is blocked'.
				($loginAttempt ? ', refusing the login attempt' : ''), Log::ERROR);
			if ($loginAttempt)
			{
				$this->responder->refuseUnchecked();
			}
			return;
		}
		if (count($blockIds) === 0)
		{
			return;
		}
		$this->logger->log('Blocked IP Address '.$ipaddress.' trying to access '.
			Origin::name($this->getApplication()->getClientId()), Log::INFO);
		if ($this->isPassedThrough($blockIds))
		{
			return;
		}
		if ($this->policy->mode() === 'loginonly' && !$this->request->isLoginAttempt())
		{
			// let the blocked IP keep browsing normally; only an actual login
			// attempt gets rejected below
			return;
		}
		$this->repositories->blocks()->recordAttempt($blockIds);
		$this->responder->refuseBlocked($ipaddress);
	}

	/**
	 * Whether a request of a client with the blocks $blockIds is let through
	 * all the same: to the unblock page with an unexpired token that was
	 * issued for one of *its own* blocks, or to the password recovery (see
	 * RequestClassifier).
	 */
	private function isPassedThrough($blockIds)
	{
		$token = $this->request->unblockPageToken();
		if ($token !== null && $this->repositories->unblockTokens()->validForBlocks($token, $blockIds))
		{
			// deliberately not logging the token: it is a bearer secret and
			// the log is readable in the backend
			$this->logger->log('Seeing a valid unblock token for this IP address, letting the request pass '.
				'through to com_bfstop', Log::INFO);
			return true;
		}
		$recovery = $this->request->passwordRecovery();
		if ($recovery !== null)
		{
			$this->logger->log('Allowing blocked IP through to the password recovery ('.$recovery.'), so a '.
				'blocked legitimate user can still recover their account', Log::INFO);
			return true;
		}
		return false;
	}
}
