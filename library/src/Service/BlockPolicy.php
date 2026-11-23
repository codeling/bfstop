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
use Codeling\Library\Bfstop\Helper\NginxDenyFile;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Codeling\Library\Bfstop\Repository\BlockRepository;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\Registry\Registry;

/**
 * What the settings make of a failed login: when its client is blocked, for
 * how long (with the escalation for repeat offenders) and how, whether the
 * blocked user may get an unblock link. Decides only: the block itself is
 * BlockService's, the answer to the client the Responder's.
 */
class BlockPolicy
{
	// how often a blocked client may submit the forms of the password
	// recovery (request a reset, confirm it with the code, set the password,
	// ask for the username) in an hour: the three steps of a reset, and some
	// room for mistakes - not a stream of mails (issue #285)
	public const RecoverySubmissionsPerHour = 10;

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

	private function intParam($name): int
	{
		return Settings::int($this->params, $name);
	}

	private function boolParam($name): bool
	{
		return Settings::bool($this->params, $name);
	}

	/** "blockMode": full, loginonly, htaccess or off */
	public function mode(): string
	{
		return Settings::string($this->params, 'blockMode');
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
		return self::realDuration($this->intParam('checkInterval'));
	}

	/** The duration of a first block, in minutes (0: permanent). */
	public function blockDuration(): int
	{
		return $this->intParam('blockDuration');
	}

	public function htaccessPath(): string
	{
		return HtaccessHelper::resolvePath(Settings::string($this->params, 'htaccessPath'));
	}

	/**
	 * The number of failed attempts allowed from a single IP before it gets
	 * blocked, adjusted by the per-attempt risk score (issue #76): a
	 * trusted-looking attempt (negative score) gets a higher threshold, a
	 * suspicious-looking one (positive score) a lower one. Floored at
	 * riskMinBlockNumber so an extreme score can never reduce this to
	 * 0-or-below and effectively instant-block a legitimate user. The floor
	 * is at most blockNumber: it lowers how far the score may reduce the
	 * threshold, it never raises the threshold of every client (the settings
	 * page refuses such a floor, a value stored otherwise is capped here).
	 */
	public function effectiveBlockNumber($riskScore): int
	{
		$blockNumber = $this->intParam('blockNumber');
		$reductionPerPoint = $this->intParam('riskBlockNumberReductionPerPoint');
		$minBlockNumber = min($this->intParam('riskMinBlockNumber'), $blockNumber);
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
			'targetedOtherAccounts' => $this->boolParam('notifyBlockedUser') &&
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
		$maxBlocksBefore = $this->intParam('maxBlocksBefore');
		$progressiveEnabled = $this->boolParam('progressiveBlockDuration');
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
	 * The nginx deny file the blocks go into (see NginxDenyFile), if the
	 * settings name one and the blocking mode is "Full Site".
	 */
	public function nginxDenyFile(): ?NginxDenyFile
	{
		return $this->mode() === 'full' ? NginxDenyFile::forSettings($this->params, $this->logger) : null;
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

	/**
	 * Whether the client $clientAddress, which is being blocked for the
	 * request $server, may be a proxy - then everybody behind it is blocked,
	 * and the administrators' mail says so (see
	 * NotifierHelper::blockedNotifyAdmin()): the request came from a
	 * non-public address with a forwarding header (an unconfigured proxy, or
	 * one whose header BFStop isn't told about), or at least two accounts
	 * have logged in from the address (one query, only if the first isn't
	 * so).
	 */
	public function mayBeProxy($clientAddress, array $server): bool
	{
		if (IpHelper::isNonPublic($clientAddress))
		{
			foreach (array_merge(IpHelper::KnownProxyHeaders, array_keys(IpHelper::UnsupportedProxyHeaders)) as $header)
			{
				if (isset($server[$header]) && trim((string) $server[$header]) !== '')
				{
					return true;
				}
			}
		}
		$key = IpHelper::trackedAddress($clientAddress, IpHelper::trustPrefixLength($this->intParam('ipv6PrefixLength')));
		return $this->repositories->knownIps()->countAccountsFrom($key) >= 2;
	}

	/** Whether blocked users may be sent an unblock link at all. */
	public function notifiesBlockedUser(): bool
	{
		return $this->boolParam('notifyBlockedUser');
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
	 * @param string|null $username              the username of the account the
	 *                                           failed login was against, if not
	 *                                           what it was typed with (an email
	 *                                           address, another case)
	 * @return string|null why no email is sent, null if it may be
	 */
	public function whyNoUnblockMail($logEntry, $clientAddress, $targetedOtherAccounts, $username = null): ?string
	{
		$username = $username ?? $logEntry->username;
		if ($targetedOtherAccounts)
		{
			return 'the failed logins from this address also targeted other accounts';
		}
		$mode = self::effectiveNotifyBlockedUser($this->intParam('notifyBlockedUser'), self::hasLiveSite());
		if ($mode === 0)
		{
			$this->logger->log('Unblock links need the site\'s address ($live_site in configuration.php): '.
				'without it, the link would have the host the request of the failed login named', Log::WARNING);
			return 'the site\'s address ($live_site) is not set';
		}
		if ($mode === self::NotifyBlockedAnyAddress)
		{
			return $this->repositories->unblockTokens()->hasCurrentFor($username)
				? 'there already is an unblock link for this user which can be used'
				: null;
		}
		return $this->repositories->knownIps()->hasLoggedInFrom($clientAddress ?? $logEntry->ipaddress,
			$username, $this->intParam('ipv6PrefixLength'))
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
}
