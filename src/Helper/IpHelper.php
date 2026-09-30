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
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Registry\Registry;

class IpHelper
{
	/**
	 * $_SERVER keys under which a reverse proxy / load balancer may report the
	 * original client IP address. None of these are trusted unless the admin
	 * explicitly enables proxy support and configures the proxy's own IP
	 * address (see the plugin's "proxy" settings fieldset) - otherwise they are
	 * trivially spoofable by any visitor and would let an attacker frame an
	 * arbitrary third-party IP address for their own failed login attempts.
	 */
	public const KnownProxyHeaders = array(
		'HTTP_X_FORWARDED_FOR',
		'HTTP_FORWARDED',
		'HTTP_X_FORWARDED',
		'HTTP_X_CLUSTER_CLIENT_IP',
		'HTTP_FORWARDED_FOR',
		'HTTP_CLIENT_IP',
	);

	/**
	 * Whether $ip lies within $subnet, given in CIDR notation (e.g.
	 * "192.0.2.0/24" or "2001:db8::/32"). Anything malformed - an address
	 * that doesn't parse, IPv4 vs. IPv6 mismatch, or a prefix length that
	 * isn't a plain number within range for the address family - never
	 * matches, so a corrupted stored entry can't turn into a wildcard.
	 */
	public static function isInSubnet($ip, $subnet)
	{
		$parts = explode('/', $subnet);
		if (count($parts) !== 2 || !preg_match('/^[0-9]{1,3}$/', $parts[1]))
		{
			return false;
		}
		$ipBin = @inet_pton($ip);
		$subnetBin = @inet_pton($parts[0]);
		if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin))
		{
			return false;
		}
		$bits = (int)$parts[1];
		if ($bits > strlen($ipBin) * 8)
		{
			return false;
		}
		$fullBytes = intdiv($bits, 8);
		if (substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes))
		{
			return false;
		}
		$remainingBits = $bits % 8;
		if ($remainingBits === 0)
		{
			return true;
		}
		$mask = (0xff << (8 - $remainingBits)) & 0xff;
		return (ord($ipBin[$fullBytes]) & $mask) === (ord($subnetBin[$fullBytes]) & $mask);
	}

	private static function firstValidPublicIP($headerValue)
	{
		foreach (explode(',', $headerValue) as $ip)
		{
			$ip = trim($ip); // just to be safe
			if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false)
			{
				return $ip;
			}
		}
		return null;
	}

	/**
	 * Determine the client IP address. By default only REMOTE_ADDR (the
	 * actual TCP peer address, which a visitor cannot forge) is used. A
	 * reverse-proxy header is only consulted if the admin has explicitly
	 * enabled proxy support and the request's REMOTE_ADDR matches the
	 * configured, trusted proxy IP address - otherwise a client could bypass
	 * the proxy entirely and spoof the header itself.
	 */
	public static function getAddress(LoggerHelper $logger)
	{
		$remoteAddr = array_key_exists('REMOTE_ADDR', $_SERVER) ? $_SERVER['REMOTE_ADDR'] : '';

		$plugin = PluginHelper::getPlugin('system', 'bfstop');
		if (!$plugin)
		{
			return $remoteAddr;
		}
		$params = new Registry($plugin->params);
		if (!(bool) $params->get('useProxy', false))
		{
			return $remoteAddr;
		}

		$proxyIpAddress = (string) $params->get('proxyIpAddress', '');
		if ($proxyIpAddress === '' || $remoteAddr !== $proxyIpAddress)
		{
			$logger->log('Proxy/load balancer usage is enabled, but the request did not originate from the '.
				'configured proxy IP address (configured: "'.$proxyIpAddress.'", actual: "'.$remoteAddr.
				'") - ignoring the proxy header and using REMOTE_ADDR!', Log::WARNING);
			return $remoteAddr;
		}

		$proxyHeaderSource = (string) $params->get('proxyHeaderSource', 'HTTP_X_FORWARDED_FOR');
		if (array_key_exists($proxyHeaderSource, $_SERVER))
		{
			$ip = self::firstValidPublicIP($_SERVER[$proxyHeaderSource]);
			if ($ip !== null)
			{
				return $ip;
			}
		}
		$logger->log('Proxy/load balancer usage is enabled, but header "'.$proxyHeaderSource.
			'" was missing or did not contain a valid public IP address, falling back to REMOTE_ADDR "'.
			$remoteAddr.'"!', Log::WARNING);
		return $remoteAddr;
	}
}
