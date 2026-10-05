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

	/**
	 * Splits the trusted proxy setting into its entries. Each entry is a
	 * single IP address or a subnet in CIDR notation; entries may be
	 * separated by comma, semicolon or whitespace. A setting holding just one
	 * address (the only form older versions knew) keeps working unchanged.
	 */
	public static function parseTrustedProxies($setting)
	{
		return preg_split('/[\s,;]+/', (string) $setting, -1, PREG_SPLIT_NO_EMPTY);
	}

	/**
	 * Whether $ip is one of the $trustedProxies (see parseTrustedProxies()).
	 * Addresses are compared in binary form, so different spellings of the
	 * same IPv6 address match.
	 */
	public static function isTrustedProxy($ip, array $trustedProxies)
	{
		$ipBin = @inet_pton((string) $ip);
		if ($ipBin === false)
		{
			return false;
		}
		foreach ($trustedProxies as $proxy)
		{
			if (strpos($proxy, '/') !== false)
			{
				if (self::isInSubnet($ip, $proxy))
				{
					return true;
				}
			}
			elseif (@inet_pton($proxy) === $ipBin)
			{
				return true;
			}
		}
		return false;
	}

	/**
	 * The address in one entry of a forwarding header, without the quotes,
	 * brackets and port the various proxies decorate it with; whatever is
	 * left is not necessarily a valid IP address.
	 */
	private static function normalizeHeaderEntry($entry)
	{
		$entry = trim(trim($entry), '"');
		if (preg_match('/^\[([^\]]+)\](?::\d+)?$/', $entry, $m) ||
			preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $entry, $m))
		{
			return $m[1];
		}
		return $entry;
	}

	/**
	 * The addresses listed in a forwarding header, in the order they appear:
	 * the leftmost one is whatever the client claimed, every further one was
	 * appended by the proxy that handled the request next. Elements that carry
	 * no address (e.g. a "Forwarded" element without for=) yield ''.
	 */
	private static function headerAddresses($headerName, $headerValue)
	{
		$addresses = array();
		foreach (explode(',', $headerValue) as $element)
		{
			if ($headerName === 'HTTP_FORWARDED')
			{
				// RFC 7239: ';'-separated key=value pairs per element
				$address = '';
				foreach (explode(';', $element) as $pair)
				{
					$keyValue = explode('=', $pair, 2);
					if (count($keyValue) === 2 && strcasecmp(trim($keyValue[0]), 'for') === 0)
					{
						$address = $keyValue[1];
						break;
					}
				}
				$element = $address;
			}
			$addresses[] = self::normalizeHeaderEntry($element);
		}
		return $addresses;
	}

	/**
	 * The client address according to a forwarding header that was set by a
	 * trusted proxy, or null if it cannot be determined reliably.
	 *
	 * Only the entries the trusted proxies themselves added can be believed,
	 * and a proxy adds its entry on the right: everything to the left of that
	 * is whatever the client (or someone upstream) put in the header, and
	 * trivially forged. So the list is read from the right, skipping the
	 * addresses of further trusted proxies (a CDN in front of a load
	 * balancer, say); the first address that is not a trusted proxy is the
	 * client. It must never be taken from further left: with a proxy that
	 * appends to an incoming X-Forwarded-For, an attacker could otherwise
	 * pick any address - to dodge blocking, to get another visitor's
	 * address blocked, or to pass as an allowlisted one.
	 */
	public static function clientAddressFromHeader($headerName, $headerValue, array $trustedProxies)
	{
		$addresses = self::headerAddresses($headerName, (string) $headerValue);
		for ($i = count($addresses) - 1; $i >= 0; --$i)
		{
			if (filter_var($addresses[$i], FILTER_VALIDATE_IP) === false)
			{
				// can't tell what this hop was; guessing from the entries
				// further left would trust forgeable data
				return null;
			}
			if (!self::isTrustedProxy($addresses[$i], $trustedProxies))
			{
				return $addresses[$i];
			}
		}
		return null;
	}

	/**
	 * Determine the client IP address. By default only REMOTE_ADDR (the
	 * actual TCP peer address, which a visitor cannot forge) is used. A
	 * reverse-proxy header is only consulted if the admin has explicitly
	 * enabled proxy support and the request's REMOTE_ADDR is one of the
	 * configured, trusted proxies - otherwise a client could bypass the proxy
	 * entirely and spoof the header itself - and even then only the part of
	 * the header the trusted proxies added is believed, see
	 * clientAddressFromHeader().
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
		$trustedProxies = self::parseTrustedProxies($proxyIpAddress);
		if (count($trustedProxies) === 0 || !self::isTrustedProxy($remoteAddr, $trustedProxies))
		{
			$logger->log('Proxy/load balancer usage is enabled, but the request did not originate from the '.
				'configured proxy IP address (configured: "'.$proxyIpAddress.'", actual: "'.$remoteAddr.
				'") - ignoring the proxy header and using REMOTE_ADDR!', Log::WARNING);
			return $remoteAddr;
		}

		$proxyHeaderSource = (string) $params->get('proxyHeaderSource', 'HTTP_X_FORWARDED_FOR');
		if (array_key_exists($proxyHeaderSource, $_SERVER))
		{
			$ip = self::clientAddressFromHeader($proxyHeaderSource, $_SERVER[$proxyHeaderSource], $trustedProxies);
			if ($ip !== null)
			{
				return $ip;
			}
		}
		$logger->log('Proxy/load balancer usage is enabled, but header "'.$proxyHeaderSource.
			'" was missing or did not end in a valid client IP address, falling back to REMOTE_ADDR "'.
			$remoteAddr.'"!', Log::WARNING);
		return $remoteAddr;
	}
}
