<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

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
			if ($db->isKnownIpUsername($ipaddress, $username))
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

	private static function commonUsernameScore(Registry $params, $username)
	{
		if (!self::getBoolParam($params, 'riskCommonUsernameEnabled', true))
		{
			return 0;
		}
		$list = (string) $params->get('riskCommonUsernames', '');
		$candidates = array_filter(array_map('trim', explode("\n", str_replace("\r", '', $list))));
		foreach ($candidates as $candidate)
		{
			if ($candidate !== '' && strcasecmp($candidate, $username) === 0)
			{
				return self::getIntParam($params, 'riskCommonUsernamePoints', 2);
			}
		}
		return 0;
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

	public static function computeScore(DatabaseHelper $db, LoggerHelper $logger, Registry $params, $ipaddress, $username)
	{
		$score = 0;
		$score += self::knownIpScore($db, $logger, $params, $ipaddress, $username);
		$score += self::commonUsernameScore($params, $username);
		$score += self::userAgentScore($params);
		return $score;
	}
}
