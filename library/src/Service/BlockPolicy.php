<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Service;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Codeling\Library\Bfstop\Helper\NotifierHelper;
use Codeling\Library\Bfstop\Repository\BlockRepository;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\Registry\Registry;

/**
 * What the settings make of a failed login: when its client is blocked, for
 * how long (with the escalation for repeat offenders) and how, whether the
 * blocked user may get an unblock link, and by how much the response is
 * delayed. Decides only: the block itself is BlockService's, the answer to
 * the client the Responder's.
 */
class BlockPolicy
{
	// values of the "notifyBlockedUser" setting besides 0 (off): 1 only to
	// users who logged in from the blocked address before, 2 for any address
	// - which needs the site's $live_site, see effectiveNotifyBlockedUser()
	public const NotifyBlockedKnownAddress = 1;
	public const NotifyBlockedAnyAddress = 2;

	private Registry $params;
	private Repositories $repositories;
	private LoginService $logins;
	private LoggerHelper $logger;

	public function __construct(Registry $params, Repositories $repositories, LoginService $logins, LoggerHelper $logger)
	{
		$this->params = $params;
		$this->repositories = $repositories;
		$this->logins = $logins;
		$this->logger = $logger;
	}

	private function intParam($name, $default): int
	{
		return (int) $this->params->get($name, $default);
	}

	private function boolParam($name, $default): bool
	{
		return (bool) $this->params->get($name, $default);
	}

	/** "blockMode": full, loginonly, htaccess or off */
	public function mode(): string
	{
		return (string) $this->params->get('blockMode', 'full');
	}

	public function isOff(): bool
	{
		return $this->mode() === 'off';
	}

	/** A duration in minutes as stored (0 or less: unlimited) as it is applied. */
	public static function realDuration($duration)
	{
		return ($duration <= 0)
			? BlockRepository::UnlimitedDuration
			: $duration;
	}

	/** The minutes within which the failed logins of an address count. */
	public function checkInterval()
	{
		return self::realDuration($this->intParam('checkInterval', Settings::Defaults['checkInterval']));
	}

	/** The duration of a first block, in minutes (0: permanent). */
	public function blockDuration(): int
	{
		return $this->intParam('blockDuration', NotifierHelper::$ONE_DAY);
	}

	public function htaccessPath(): string
	{
		return HtaccessHelper::resolvePath((string) $this->params->get('htaccessPath', ''));
	}

	/**
	 * The number of failed attempts allowed from a single IP before it gets
	 * blocked, adjusted by the per-attempt risk score (issue #76): a
	 * trusted-looking attempt (negative score) gets a higher threshold, a
	 * suspicious-looking one (positive score) a lower one. Floored at
	 * riskMinBlockNumber so an extreme score can never reduce this to
	 * 0-or-below and effectively instant-block a legitimate user.
	 */
	public function effectiveBlockNumber($riskScore): int
	{
		$blockNumber = $this->intParam('blockNumber', Settings::Defaults['blockNumber']);
		$reductionPerPoint = $this->intParam('riskBlockNumberReductionPerPoint', 1);
		$minBlockNumber = $this->intParam('riskMinBlockNumber', 2);
		$effective = (int) round($blockNumber - $riskScore * $reductionPerPoint);
		return max($minBlockNumber, $effective);
	}

	private function countedFailedLogins($logEntry): int
	{
		return (int) $this->repositories->failedLogins()->countUnhandledFromAddress(
			$this->checkInterval(), $logEntry->ipaddress, $logEntry->logtime);
	}

	/**
	 * How many more failed logins the client of $logEntry (which is counted
	 * already) has before it is blocked: none (0 or less) means it is to be
	 * blocked now. One query; the plugin asks once per failed login, for the
	 * message of the remaining attempts and the decision.
	 */
	public function attemptsLeft($logEntry, $riskScore): int
	{
		$allowed = $this->effectiveBlockNumber($riskScore);
		$counted = $this->countedFailedLogins($logEntry);
		$this->logger->log("Failed logins: $counted; allowed: $allowed", Log::DEBUG);
		return $allowed - $counted;
	}

	/**
	 * How the client of $logEntry is blocked, if it isn't yet; called under
	 * the lock of BlockService::withLock().
	 *
	 * @param object      $logEntry      the failed login which led to the block
	 * @param string|null $clientAddress the client's actual address, if the
	 *                                   entry has the key it is tracked under
	 * @return array|null null if it is blocked already, else
	 *                    - duration: of the block, in minutes (0: permanent)
	 *                    - throughFile: whether blocks go into .htaccess
	 *                    - htaccess: whether this one does (see htaccessAllowed())
	 *                    - htaccessEntry: what the file gets for it (see
	 *                      HtaccessHelper::entryFor())
	 *                    - htaccessPath: the directory of the file
	 *                    - targetedOtherAccounts: whether the failed logins
	 *                      which led to it also went against other accounts
	 */
	public function decide($logEntry, $clientAddress = null): ?array
	{
		// a parallel request of the same client may have blocked it while
		// this one waited for the lock
		if ($this->repositories->blocks()->isBlocked($clientAddress ?? $logEntry->ipaddress))
		{
			$this->logger->log('IP '.$logEntry->ipaddress.' is already blocked', Log::INFO);
			return null;
		}
		$throughFile = $this->mode() === 'htaccess';
		$htaccessEntry = HtaccessHelper::entryFor($logEntry->ipaddress, $clientAddress);
		return array(
			'duration' => $this->escalatedDuration($logEntry->ipaddress, $this->blockDuration()),
			'throughFile' => $throughFile,
			// what the web server turns away is the entry, not all of the
			// block: the allow list and the proxies matter within the entry
			'htaccess' => $throughFile && $this->htaccessAllowed($htaccessEntry),
			'htaccessEntry' => $htaccessEntry,
			'htaccessPath' => $this->htaccessPath(),
			// has to be found out before blocking, which marks these failed
			// logins as handled
			'targetedOtherAccounts' => $this->boolParam('notifyBlockedUser', false) &&
				$this->logins->hasFailedLoginsForOtherAccounts($this->checkInterval(),
					$logEntry->ipaddress, $logEntry->username, $logEntry->logtime),
		);
	}

	/**
	 * The duration of a block of $address, after its earlier blocks: permanent
	 * after maxBlocksBefore of them, and with "progressiveBlockDuration"
	 * doubled for each one.
	 */
	public function escalatedDuration($address, $duration)
	{
		$maxBlocksBefore = $this->intParam('maxBlocksBefore', Settings::Defaults['maxBlocksBefore']);
		$progressiveEnabled = $this->boolParam('progressiveBlockDuration', false);
		if ($maxBlocksBefore <= 0 && !$progressiveEnabled)
		{
			return $duration;
		}
		$numberOfPrevBlocks = $this->repositories->blocks()->countPrevious($address);
		$this->logger->log('Number of previous blocks for IP='.$address.': '.$numberOfPrevBlocks, Log::DEBUG);
		if ($maxBlocksBefore > 0 && $numberOfPrevBlocks >= $maxBlocksBefore)
		{
			$this->logger->log('Number of previous blocks exceeds configured maximum, blocking permanently!', Log::INFO);
			return 0;
		}
		if ($progressiveEnabled && $duration > 0 && $numberOfPrevBlocks > 0)
		{
			// doubles the block duration per repeat offense, capped at
			// 2^6=64x, mirroring OWASP's doubling-lockout-duration
			// recommendation
			$multiplier = 2 ** min($numberOfPrevBlocks, 6);
			$newDuration = $duration * $multiplier;
			$this->logger->log('Progressive block duration: '.$numberOfPrevBlocks.' previous block(s), scaling '.
				'duration '.$duration.' by '.$multiplier.'x to '.$newDuration, Log::INFO);
			return $newDuration;
		}
		return $duration;
	}

	/**
	 * Whether $address may be blocked through the .htaccess file, not only in
	 * the database: the web server turns away whatever the entry covers,
	 * before Joomla - and the allow list - get a say.
	 */
	public function htaccessAllowed($address): bool
	{
		if (IpHelper::overlapsTrustedProxy($address, IpHelper::trustedProxies()))
		{
			// the failed logins came through a trusted proxy without a
			// forwarding header which tells the client (see getAddress()):
			// in the .htaccess file, this would turn away everybody coming
			// through the proxy, so it is only blocked in the database
			$this->logger->log('Not blocking '.$address.' through .htaccess: it is (or contains) a '.
				'trusted proxy - check that the proxy sends the configured header', Log::ERROR);
			return false;
		}
		// the web server knows nothing of the allow list: a network block
		// (an IPv6 client gets its /64, see HtaccessHelper::entryFor())
		// would turn away the allowed addresses in it before Joomla runs
		$allowed = $this->repositories->allowList()->entriesOverlapping($address);
		if ($allowed === null || count($allowed) > 0)
		{
			$this->logger->log('Not blocking '.$address.' through .htaccess: it contains '.
				($allowed === null ? 'addresses of the allow list (which could not be read)'
					: 'allowed address(es) '.implode(', ', $allowed)).' - it is only blocked in the database',
				Log::WARNING);
			return false;
		}
		return true;
	}

	/** Whether blocked users may be sent an unblock link at all. */
	public function notifiesBlockedUser(): bool
	{
		return $this->boolParam('notifyBlockedUser', false);
	}

	/**
	 * Anybody can make the plugin send an unblock email to a user: by failing
	 * to log in with that username from an IP address until it is blocked.
	 * No email is sent without the site's address, see
	 * effectiveNotifyBlockedUser(). To keep it from being used to flood
	 * somebody's inbox:
	 *
	 * - by default (mode 1) the email is only sent if the user has logged in
	 *   from the blocked IP address before - which is where somebody
	 *   locking themselves out comes from, but never an attacker's address;
	 * - if it is to go to any address (mode 2), at most one email which can
	 *   still be used is out for a user at any time.
	 *
	 * In either mode it isn't sent if the failed logins which got the address
	 * blocked also went against other accounts: the link unblocks the
	 * address, and whoever caused that could just as well own this account -
	 * and would get to continue with the other accounts by following it.
	 *
	 * @param object      $logEntry              the failed login which led to the block
	 * @param string|null $clientAddress         see decide()
	 * @param bool        $targetedOtherAccounts see decide()
	 * @return string|null why no email is sent, null if it may be
	 */
	public function whyNoUnblockMail($logEntry, $clientAddress, $targetedOtherAccounts): ?string
	{
		if ($targetedOtherAccounts)
		{
			return 'the failed logins from this address also targeted other accounts';
		}
		$mode = self::effectiveNotifyBlockedUser($this->intParam('notifyBlockedUser', 0), self::hasLiveSite());
		if ($mode === 0)
		{
			$this->logger->log('Unblock links need the site\'s address ($live_site in configuration.php): '.
				'without it, the link would have the host the request of the failed login named', Log::WARNING);
			return 'the site\'s address ($live_site) is not set';
		}
		if ($mode === self::NotifyBlockedAnyAddress)
		{
			return $this->repositories->unblockTokens()->hasCurrentFor($logEntry->username)
				? 'there already is an unblock link for this user which can be used'
				: null;
		}
		return $this->repositories->knownIps()->hasLoggedInFrom($clientAddress ?? $logEntry->ipaddress,
			$logEntry->username, $this->intParam('ipv6PrefixLength', Settings::Defaults['ipv6PrefixLength']))
			? null
			: 'the user has never logged in from this IP address';
	}

	/**
	 * Whether the site's address is configured ($live_site in
	 * configuration.php). Without it, Joomla builds every address it links to
	 * - also Uri::root(), and so the unblock link - from the host the request
	 * names, which is whatever the client sent.
	 */
	public static function hasLiveSite(): bool
	{
		return trim((string) Factory::getApplication()->get('live_site', '')) !== '';
	}

	/**
	 * The "notifyBlockedUser" setting as it is applied. The unblock email is
	 * prepared in the request of the failed login which got the address
	 * blocked, so the link in it has the host that request named, unless
	 * $live_site is set - and whoever sends that request picks the host. Mode
	 * 1 doesn't make that request trustworthy: it only says that the user has
	 * logged in from the address before, and clients are tracked by their
	 * network (an IPv6 /56, see IpHelper::trackedAddress()) behind which there
	 * may be many other people (a NAT, an office, a campus). Any of them could
	 * get a real mail of the site sent to the user with a link to their own
	 * server (phishing; and mail scanners open every link, handing them the
	 * token). So without $live_site, no unblock link is sent at all. The
	 * settings page doesn't take modes 1 and 2 without $live_site; this covers
	 * a setting saved before, or $live_site removed later.
	 */
	public static function effectiveNotifyBlockedUser($setting, $hasLiveSite): int
	{
		$setting = (int) $setting;
		return $hasLiveSite ? $setting : 0;
	}

	/**
	 * By how many seconds the response to the failed login $logEntry is held
	 * back (before Responder::delay() caps it): the account throttle, the
	 * delay for the attack volume, and the one for the risk score of the
	 * attempt.
	 */
	public function delaySeconds($logEntry, $riskScore)
	{
		return $this->accountThrottleDelay($logEntry) + $this->determineDelayDuration($riskScore);
	}

	/**
	 * Account-level throttle: once a username has accumulated enough failed
	 * attempts *from any source IP combined* within the configured window,
	 * every further failed attempt for that username gets an extra forced
	 * delay. Unlike the block (which is scoped to a single IP), this catches
	 * an attacker who distributes attempts against one target account across
	 * many different IPs - a distributed attack no per-IP threshold can ever
	 * detect on its own. The account itself is never locked - only wrong
	 * attempts get progressively expensive, so a correct password still logs
	 * the real owner in immediately.
	 *
	 * @return int the seconds to delay the response by
	 */
	private function accountThrottleDelay($logEntry): int
	{
		if (!$this->boolParam('accountThrottleEnabled', true))
		{
			return 0;
		}
		$checkInterval = $this->intParam('accountCheckInterval', 60);
		$accountBlockNumber = $this->intParam('accountBlockNumber', 20);
		$numberOfFailedLogins = $this->repositories->failedLogins()->countUnhandledForUsername(
			$checkInterval, $logEntry->username, $logEntry->logtime);
		if ($numberOfFailedLogins < $accountBlockNumber)
		{
			return 0;
		}
		$throttleDelay = max(0, $this->intParam('accountThrottleDelay', 5));
		if ($throttleDelay > 0)
		{
			$this->logger->log('Account-level throttle triggered for username \''.
				$logEntry->username.'\' ('.$numberOfFailedLogins.
				' failed attempts across all IPs within '.$checkInterval.
				' minutes), adding '.$throttleDelay.'s delay', Log::INFO);
		}
		return $throttleDelay;
	}

	/**
	 * The global-attack-volume-based delay, plus an additional delay
	 * proportional to the per-attempt risk score (issue #76) - the two are
	 * independent, orthogonal mechanisms; only a positive (suspicious) score
	 * adds delay, a trust bonus never reduces it below the base.
	 */
	private function determineDelayDuration($riskScore)
	{
		$riskDelaySecondsPerPoint = $this->intParam('riskDelaySecondsPerPoint',
			Settings::Defaults['riskDelaySecondsPerPoint']);
		return $this->determineBaseDelayDuration() + max(0, $riskScore) * $riskDelaySecondsPerPoint;
	}

	private function determineBaseDelayDuration()
	{
		$delayDuration = $this->intParam('delayDuration', 0);
		if (!$this->boolParam('adaptiveDelay', false))
		{
			return $delayDuration;
		}
		$maxDelay = $this->intParam('adaptiveDelayMax', Settings::Defaults['adaptiveDelayMax']);
		$lowThreshold = $this->intParam('adaptiveDelayThresholdMin', Settings::Defaults['adaptiveDelayThresholdMin']);
		$highThreshold = $this->intParam('adaptiveDelayThresholdMax', Settings::Defaults['adaptiveDelayThresholdMax']);
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
		$recentFailed = min($this->repositories->failedLogins()->countInLastHour(), $highThreshold);
		if ($recentFailed > $lowThreshold)
		{
			return $delayDuration + ($recentFailed - $lowThreshold)
				* ($maxDelay - $delayDuration)
				/ ($highThreshold - $lowThreshold);
		}
		return $delayDuration;
	}
}
