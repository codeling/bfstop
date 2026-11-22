<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Helper;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Log\Log;
use Joomla\Registry\Registry;

/**
 * Computes a signed per-attempt risk score for a failed login (issue #76).
 * Positive contributions mean "more suspicious" (allow fewer attempts);
 * negative contributions mean "more trusted" (allow more), see
 * BlockPolicy::effectiveBlockNumber().
 * Every signal is independently toggleable and fails safe: any internal
 * error is logged and contributes 0, never blocks or throws.
 */
class RiskHelper
{
	private static function knownIpScore(Repositories $repositories, LoggerHelper $logger, Registry $params, $ipaddress, $username)
	{
		if (!Settings::bool($params, 'riskKnownIpEnabled'))
		{
			return 0;
		}
		try
		{
			if ($repositories->knownIps()->hasLoggedInFrom($ipaddress, $username, Settings::int($params, 'ipv6PrefixLength')))
			{
				return -Settings::int($params, 'riskKnownIpPoints');
			}
		}
		catch (\Throwable $e)
		{
			$logger->log('RiskHelper: known-IP lookup failed: '.$e->getMessage(), Log::WARNING);
		}
		return 0;
	}

	/**
	 * Whether $username is on the admin's list of common/high-value
	 * usernames (case-insensitive).
	 */
	public static function isCommonUsername(Registry $params, $username)
	{
		$list = Settings::string($params, 'riskCommonUsernames');
		$candidates = array_filter(array_map('trim', explode("\n", str_replace("\r", '', $list))));
		foreach ($candidates as $candidate)
		{
			if ($candidate !== '' && strcasecmp($candidate, $username) === 0)
			{
				return true;
			}
		}
		return false;
	}

	private static function commonUsernameScore(Registry $params, $username)
	{
		if (!Settings::bool($params, 'riskCommonUsernameEnabled'))
		{
			return 0;
		}
		return self::isCommonUsername($params, $username)
			? Settings::int($params, 'riskCommonUsernamePoints')
			: 0;
	}

	private static function userAgentScore(Registry $params)
	{
		if (!Settings::bool($params, 'riskUserAgentEnabled'))
		{
			return 0;
		}
		$userAgent = array_key_exists('HTTP_USER_AGENT', $_SERVER) ? trim($_SERVER['HTTP_USER_AGENT']) : '';
		if ($userAgent === '')
		{
			return Settings::int($params, 'riskUserAgentPoints');
		}
		return 0;
	}

	/**
	 * Off by default (unlike the signals above): needs a GeoLite2-Country
	 * (or City) database configured via geoDbPath (shared with the IP-info
	 * display, issue #169) and at least one "home country" configured to be
	 * able to do anything at all.
	 */
	private static function geoScore(LoggerHelper $logger, Registry $params, $ipaddress)
	{
		if (!Settings::bool($params, 'riskGeoEnabled'))
		{
			return 0;
		}
		$dbPath = Settings::string($params, 'geoDbPath');
		$countryCode = GeoHelper::getCountryCode($logger, $dbPath, $ipaddress);
		if ($countryCode === null)
		{
			return 0;
		}
		$homeCountries = Settings::string($params, 'riskGeoHomeCountries');
		$homeList = array_filter(array_map('trim', explode(',', strtoupper($homeCountries))));
		if (empty($homeList) || in_array(strtoupper($countryCode), $homeList, true))
		{
			return 0;
		}
		return Settings::int($params, 'riskGeoPoints');
	}

	/**
	 * Off by default: a reverse lookup asks the name servers of whoever owns
	 * the address, who can make it slow. So the lookup is limited in time
	 * (DnsHelper::reverseLookup(), not gethostbyaddr(), which can't be) and
	 * its result cached by the key the client is tracked under (an IPv6
	 * client by its network: it could otherwise miss the cache with every
	 * request, switching addresses), see DnsCacheRepository::get().
	 * A lookup which gets no answer in time counts as no record.
	 */
	private static function reverseDnsScore(Repositories $repositories, LoggerHelper $logger, Registry $params, $ipaddress, $cacheKey)
	{
		if (!Settings::bool($params, 'riskReverseDnsEnabled'))
		{
			return 0;
		}
		try
		{
			$hostname = $repositories->dnsCache()->get($cacheKey);
			if ($hostname === false)
			{
				$hostname = DnsHelper::reverseLookup($ipaddress);
				if ($hostname === false)
				{
					$logger->log('RiskHelper: no name server found in '.DnsHelper::DefaultResolvConf.
						', the reverse DNS signal is skipped', Log::WARNING);
					return 0;
				}
				$repositories->dnsCache()->put($cacheKey, $hostname);
			}
			if ($hostname === null)
			{
				return Settings::int($params, 'riskReverseDnsPoints');
			}
		}
		catch (\Throwable $e)
		{
			$logger->log('RiskHelper: reverse DNS lookup failed: '.$e->getMessage(), Log::WARNING);
		}
		return 0;
	}

	/**
	 * A distributed attack on one account: once the username of the failed
	 * login $failedLogin (as stored, see the plugin's usernameForStorage())
	 * has had "accountBlockNumber" failed logins within "accountCheckInterval"
	 * minutes, from whatever addresses (the failed login itself included),
	 * every address trying it is allowed fewer attempts. A per-address
	 * threshold alone never notices an attacker who spreads the attempts on
	 * one account over many addresses (issue #76). The account itself is never
	 * locked: the real owner, from an address they logged in from before, is
	 * still trusted by the known-IP signal. Until 2.0.0, this was a delay of
	 * the response instead, which held a PHP worker and did not slow down an
	 * attacker who doesn't wait for the answers.
	 */
	private static function accountAttackScore(Repositories $repositories, LoggerHelper $logger, Registry $params, $failedLogin)
	{
		if ($failedLogin === null || !Settings::bool($params, 'accountAttackEnabled'))
		{
			return 0;
		}
		try
		{
			$minutes = Settings::int($params, 'accountCheckInterval');
			$count = (int) $repositories->failedLogins()->countUnhandledForUsername($minutes,
				$failedLogin->username, $failedLogin->logtime);
			if ($count >= Settings::int($params, 'accountBlockNumber'))
			{
				$logger->log('Account under attack: '.$count.' failed logins for username \''.$failedLogin->username.
					'\' within '.$minutes.' minutes, from any address', Log::INFO);
				return Settings::int($params, 'accountAttackPoints');
			}
		}
		catch (\Throwable $e)
		{
			$logger->log('RiskHelper: count of failed logins of the account failed: '.$e->getMessage(), Log::WARNING);
		}
		return 0;
	}

	/**
	 * @param string|null $trackedAddress the key the client is tracked under
	 *                                    (IpHelper::trackedAddress()), if not
	 *                                    its address
	 * @param object|null $failedLogin    the failed login as recorded (its
	 *                                    username as stored, and its logtime),
	 *                                    for the signal of a distributed attack
	 *                                    on one account; without it, that
	 *                                    signal is skipped
	 */
	public static function computeScore(Repositories $repositories, LoggerHelper $logger, Registry $params, $ipaddress, $username,
		$trackedAddress = null, $failedLogin = null)
	{
		$score = 0;
		$score += self::knownIpScore($repositories, $logger, $params, $ipaddress, $username);
		$score += self::commonUsernameScore($params, $username);
		$score += self::userAgentScore($params);
		$score += self::geoScore($logger, $params, $ipaddress);
		$score += self::reverseDnsScore($repositories, $logger, $params, $ipaddress, $trackedAddress ?? $ipaddress);
		$score += self::accountAttackScore($repositories, $logger, $params, $failedLogin);
		return $score;
	}
}
