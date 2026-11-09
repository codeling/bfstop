<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Extension\Bfstop;
use Joomla\CMS\Log\Log;
use Joomla\Registry\Registry;

/**
 * Computes a signed per-attempt risk score for a failed login (issue #76).
 * Positive contributions mean "more suspicious" (allow fewer attempts,
 * add more delay); negative contributions mean "more trusted" (allow more).
 * Every signal is independently toggleable and fails safe: any internal
 * error is logged and contributes 0, never blocks or throws.
 */
class RiskHelper
{
	private static function getBoolParam(Registry $params, $paramName, $default)
	{
		return (bool) $params->get($paramName, $default);
	}

	private static function getIntParam(Registry $params, $paramName, $default)
	{
		return (int) $params->get($paramName, $default);
	}

	private static function knownIpScore(DatabaseHelper $db, LoggerHelper $logger, Registry $params, $ipaddress, $username)
	{
		if (!self::getBoolParam($params, 'riskKnownIpEnabled', true))
		{
			return 0;
		}
		try
		{
			if ($db->hasLoggedInFrom($ipaddress, $username, self::getIntParam($params, 'ipv6PrefixLength', Bfstop::DefaultSettings['ipv6PrefixLength'])))
			{
				return -self::getIntParam($params, 'riskKnownIpPoints', 5);
			}
		}
		catch (\Exception $e)
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
		$list = (string) $params->get('riskCommonUsernames', Bfstop::DefaultSettings['riskCommonUsernames']);
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
		if (!self::getBoolParam($params, 'riskCommonUsernameEnabled', true))
		{
			return 0;
		}
		return self::isCommonUsername($params, $username)
			? self::getIntParam($params, 'riskCommonUsernamePoints', 2)
			: 0;
	}

	private static function userAgentScore(Registry $params)
	{
		if (!self::getBoolParam($params, 'riskUserAgentEnabled', true))
		{
			return 0;
		}
		$userAgent = array_key_exists('HTTP_USER_AGENT', $_SERVER) ? trim($_SERVER['HTTP_USER_AGENT']) : '';
		if ($userAgent === '')
		{
			return self::getIntParam($params, 'riskUserAgentPoints', 2);
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
		if (!self::getBoolParam($params, 'riskGeoEnabled', false))
		{
			return 0;
		}
		$dbPath = (string) $params->get('geoDbPath', '');
		$countryCode = GeoHelper::getCountryCode($logger, $dbPath, $ipaddress);
		if ($countryCode === null)
		{
			return 0;
		}
		$homeCountries = (string) $params->get('riskGeoHomeCountries', '');
		$homeList = array_filter(array_map('trim', explode(',', strtoupper($homeCountries))));
		if (empty($homeList) || in_array(strtoupper($countryCode), $homeList, true))
		{
			return 0;
		}
		return self::getIntParam($params, 'riskGeoPoints', 3);
	}

	/**
	 * Off by default: a reverse lookup asks the name servers of whoever owns
	 * the address, who can make it slow. So the lookup is limited in time
	 * (DnsHelper::reverseLookup(), not gethostbyaddr(), which can't be) and
	 * its result cached by the key the client is tracked under (an IPv6
	 * client by its network: it could otherwise miss the cache with every
	 * request, switching addresses), see DatabaseHelper::getCachedHostname().
	 * A lookup which gets no answer in time counts as no record.
	 */
	private static function reverseDnsScore(DatabaseHelper $db, LoggerHelper $logger, Registry $params, $ipaddress, $cacheKey)
	{
		if (!self::getBoolParam($params, 'riskReverseDnsEnabled', false))
		{
			return 0;
		}
		try
		{
			$hostname = $db->getCachedHostname($cacheKey);
			if ($hostname === false)
			{
				$hostname = DnsHelper::reverseLookup($ipaddress);
				if ($hostname === false)
				{
					$logger->log('RiskHelper: no name server found in '.DnsHelper::DefaultResolvConf.
						', the reverse DNS signal is skipped', Log::WARNING);
					return 0;
				}
				$db->cacheHostname($cacheKey, $hostname);
			}
			if ($hostname === null)
			{
				return self::getIntParam($params, 'riskReverseDnsPoints', 2);
			}
		}
		catch (\Exception $e)
		{
			$logger->log('RiskHelper: reverse DNS lookup failed: '.$e->getMessage(), Log::WARNING);
		}
		return 0;
	}

	/**
	 * @param string|null $trackedAddress the key the client is tracked under
	 *                                    (IpHelper::trackedAddress()), if not
	 *                                    its address
	 */
	public static function computeScore(DatabaseHelper $db, LoggerHelper $logger, Registry $params, $ipaddress, $username,
		$trackedAddress = null)
	{
		$score = 0;
		$score += self::knownIpScore($db, $logger, $params, $ipaddress, $username);
		$score += self::commonUsernameScore($params, $username);
		$score += self::userAgentScore($params);
		$score += self::geoScore($logger, $params, $ipaddress);
		$score += self::reverseDnsScore($db, $logger, $params, $ipaddress, $trackedAddress ?? $ipaddress);
		return $score;
	}
}
