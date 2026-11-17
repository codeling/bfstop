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
 * LoginTurn (Service namespace of the plugin).
 */
class Bfstop extends CMSPlugin implements SubscriberInterface
{
	// the language is loaded by init(), when the plugin handles an event (as
	// Joomla 6 does it): by the constructor, before the plugin has its
	// application, Joomla 5 would take it from Factory::getLanguage(), which
	// is deprecated
	protected $autoloadLanguage = false;
	private bool $languageLoaded = false;

	/**
	 * Values the plugin keeps among its settings for itself, which saving the
	 * settings page must keep: none any more - its bookkeeping is the table
	 * #__bfstop_state, which that page can't overwrite. com_bfstop's
	 * SettingsModel::keepInternalSettings() went through this until it was
	 * removed there; then so can this.
	 */
	public const InternalSettings = array();

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
		return array(
			'onUserLoginFailure' => 'onUserLoginFailure',
			'onUserLogin'        => 'onUserLogin',
			'onAfterInitialise'  => 'onAfterInitialise',
			'onAfterRoute'       => 'onAfterRoute',
			'onAfterApiRoute'    => 'onAfterApiRoute',
		);
	}

	private function intParam($paramName, $default)
	{
		return (int) $this->params->get($paramName, $default);
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
				$this->params->get('emailaddress', ''),
				$this->intParam('userID', -1),
				$this->intParam('userGroup', -1),
				(bool) $this->params->get('groupNotificationEnabled', false));
		}
		return $this->notifier;
	}

	private function isEnabledForCurrentOrigin()
	{
		return Origin::isEnabled($this->params->get('enabledForOrigin', Settings::Defaults['enabledForOrigin']),
			$this->getApplication());
	}

	private function trackedAddress($ipAddress)
	{
		return IpHelper::trackedAddress($ipAddress, $this->intParam('ipv6PrefixLength', Settings::Defaults['ipv6PrefixLength']));
	}

	/**
	 * The form in which the username of a failed login is stored, mailed and
	 * logged, see UsernameHelper.
	 */
	private function usernameForStorage($username)
	{
		$mode = (string) $this->params->get('unknownUsernameMode', UsernameHelper::ModeHash);
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
		if (empty($ipAddress) || $ipAddress === '')
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

		// remaining attempts notification only makes sense if we actually
		// block (and the count needs a query, which is saved otherwise)
		if (!$this->policy->isOff() && $this->responder->showsRemainingAttempts())
		{
			$this->responder->showRemainingAttempts($this->policy->attemptsLeft($logEntry, $riskScore));
		}

		if ($this->policy->isTooManyAttempts($logEntry, $riskScore))
		{
			$this->block($logEntry);
		}
		// counted, and blocked if that was one too many: the next login of
		// this address may be handled (see LoginTurn). The mail below and the
		// delay take time it needn't wait for
		$this->loginTurn->end();

		// $username is what was typed; the entry only holds a hash of it if
		// it isn't an account (see usernameForStorage())
		if ((bool) $this->params->get('notifyFailedOnlyExisting', false) &&
			!$this->isAccount($username))
		{
			$this->logger->log('Not notifying of failed login: the username does not belong to an account', Log::DEBUG);
		}
		else
		{
			$this->notifier()->failedLogin($logEntry, $this->intParam('notifyFailedNumber', 0));
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
			$this->intParam('notifyBlockedNumber', 5));
		if (!$this->policy->notifiesBlockedUser())
		{
			return;
		}
		$userEmail = $this->repositories->users()->emailByUsername($logEntry->username);
		if ($userEmail == null)
		{
			$this->logger->log('Unknown user ('.$logEntry->username.') blocked, not sending any notifications', Log::DEBUG);
			return;
		}
		$withheld = $this->policy->whyNoUnblockMail($logEntry, $this->clientAddress, $targetedOtherAccounts);
		if ($withheld !== null)
		{
			$this->logger->log("Existing user '".$logEntry->username."' was blocked, but ".$withheld.
				' - not sending unblock instructions', Log::INFO);
			return;
		}
		$this->logger->log("Existing user '".$logEntry->username."' was blocked, sending unblock instructions", Log::INFO);
		$token = $this->repositories->unblockTokens()->add($id, TokenHelper::getToken($this->logger), $logEntry->username);
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
		$info = new \stdClass();
		$info->ipaddress = IpHelper::getAddress($this->logger);
		$info->username = (string) ($user['username'] ?? '');
		$this->logger->log('Successful login by '.$info->username.
			' from IP address '.$info->ipaddress, Log::DEBUG);
		$this->logins->recordSuccessfulLogin($info, $this->trackedAddress($info->ipaddress),
			IpHelper::trackedAddress($info->ipaddress, IpHelper::trustPrefixLength(
				$this->intParam('ipv6PrefixLength', Settings::Defaults['ipv6PrefixLength']))));
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
