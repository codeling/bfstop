<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Helper;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Log\Log;

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
		self::CloudflareHeader,
	);

	/**
	 * Cloudflare's header: Cloudflare sets it on every request it forwards,
	 * overwriting whatever the visitor sent, and it always holds exactly one
	 * address - so it is only taken if it is exactly that (see
	 * clientAddressFromHeader()).
	 */
	public const CloudflareHeader = 'HTTP_CF_CONNECTING_IP';

	/**
	 * Headers of proxies and CDNs which carry the visitor's address, but which
	 * BFStop doesn't read: they are recognised, to tell the administrator
	 * that the proxy sends one of them and what to do instead (see the setup
	 * assistant). X-Real-IP holds what X-Forwarded-For's last entry holds
	 * where a proxy sets it, and is passed on as the visitor sent it where
	 * none does; Fastly-Client-IP can be forged unless the site's own
	 * configuration overwrites it; True-Client-IP is rare (Akamai and
	 * Cloudflare Enterprise, which sends CF-Connecting-IP too). The others
	 * are each one provider's, which append to X-Forwarded-For as well.
	 * $_SERVER key => the header's name.
	 */
	public const UnsupportedProxyHeaders = array(
		'HTTP_X_REAL_IP' => 'X-Real-IP',
		'HTTP_TRUE_CLIENT_IP' => 'True-Client-IP',
		'HTTP_FASTLY_CLIENT_IP' => 'Fastly-Client-IP',
		'HTTP_X_CLIENT_IP' => 'X-Client-IP',
		'HTTP_X_AZURE_CLIENTIP' => 'X-Azure-ClientIP',
		'HTTP_X_AZURE_SOCKETIP' => 'X-Azure-SocketIP',
		'HTTP_X_ENVOY_EXTERNAL_ADDRESS' => 'X-Envoy-External-Address',
		'HTTP_CLOUDFRONT_VIEWER_ADDRESS' => 'CloudFront-Viewer-Address',
		'HTTP_FLY_CLIENT_IP' => 'Fly-Client-IP',
	);

	/**
	 * The name of the header of the $_SERVER key $key, as it is written
	 * ("HTTP_X_FORWARDED_FOR": "X-Forwarded-For").
	 */
	public static function headerName($key): string
	{
		$key = (string) $key;
		if ($key === self::CloudflareHeader)
		{
			return 'CF-Connecting-IP';
		}
		if (isset(self::UnsupportedProxyHeaders[$key]))
		{
			return self::UnsupportedProxyHeaders[$key];
		}
		return str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', preg_replace('/^HTTP_/', '', $key)))));
	}

	/**
	 * Whether $ip lies within $subnet, given in CIDR notation (e.g.
	 * "192.0.2.0/24" or "2001:db8::/32"). Anything malformed - an address
	 * that doesn't parse, IPv4 vs. IPv6 mismatch, or a prefix length that
	 * isn't a plain number within range for the address family - never
	 * matches, so a corrupted stored entry can't turn into a wildcard.
	 * IPv4-mapped IPv6 addresses and networks are compared as IPv4, see
	 * unmapped().
	 */
	public static function isInSubnet($ip, $subnet)
	{
		// an IPv4-mapped address is the IPv4 address, see unmapped()
		$ip = self::unmapped($ip);
		$subnet = self::unmapped($subnet);
		$parts = explode('/', $subnet);
		if (count($parts) !== 2 || !preg_match('/^[0-9]{1,3}\z/', $parts[1]))
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
	 * The networks whose addresses are not on the public internet: private
	 * (RFC 1918, IPv6 unique local), loopback, shared address space of
	 * carrier-grade NAT (RFC 6598) and link-local. A proxy or load balancer
	 * in front of a site usually reaches it from one of them.
	 */
	public const NonPublicNetworks = array('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
		'100.64.0.0/10', '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10');

	/**
	 * Whether $ip is an address of one of the NonPublicNetworks (an
	 * IPv4-mapped one as the IPv4 address); false for what is no address.
	 */
	public static function isNonPublic($ip): bool
	{
		$ip = self::unmapped(trim((string) $ip));
		if (filter_var($ip, FILTER_VALIDATE_IP) === false)
		{
			return false;
		}
		foreach (self::NonPublicNetworks as $network)
		{
			if (self::isInSubnet($ip, $network))
			{
				return true;
			}
		}
		return false;
	}

	/**
	 * The last entry of the forwarding header $headerName with the value
	 * $headerValue (the one the proxy next to the web server added), as an
	 * address; null if it isn't one.
	 */
	public static function lastHeaderAddress($headerName, $headerValue): ?string
	{
		if ($headerName === self::CloudflareHeader)
		{
			return self::clientAddressFromHeader($headerName, $headerValue, array());
		}
		$addresses = self::headerAddresses($headerName, (string) $headerValue);
		$last = (string) end($addresses);
		return filter_var($last, FILTER_VALIDATE_IP) !== false ? self::unmapped($last) : null;
	}

	/**
	 * Whether $value is a single IP address or a subnet in CIDR notation
	 * (prefix length a plain number within range for the address family) -
	 * and nothing else: no whitespace, no further text. Used before anything
	 * is written to a configuration file.
	 */
	public static function isValidIpOrSubnet($value)
	{
		$parts = explode('/', (string) $value);
		if (count($parts) > 2 || filter_var($parts[0], FILTER_VALIDATE_IP) === false)
		{
			return false;
		}
		if (count($parts) === 1)
		{
			return true;
		}
		return preg_match('/^[0-9]{1,3}\z/', $parts[1]) === 1 &&
			(int) $parts[1] <= (strpos($parts[0], ':') !== false ? 128 : 32);
	}

	/**
	 * The network mask of a prefix length of $bits, as a binary string of
	 * $length bytes (16 for IPv6, 4 for IPv4).
	 */
	public static function prefixMask($bits, $length = 16)
	{
		$mask = str_repeat("\xff", intdiv($bits, 8));
		if ($bits % 8 > 0)
		{
			$mask .= chr((0xff << (8 - $bits % 8)) & 0xff);
		}
		return str_pad($mask, $length, "\x00");
	}

	// the first 12 bytes of an IPv4-mapped IPv6 address, ::ffff:0:0/96
	private const MappedPrefix = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";

	/**
	 * $value - an address, or a network in CIDR notation - with an
	 * IPv4-mapped IPv6 address (::ffff:203.0.113.5) as the IPv4 address it
	 * stands for, and a network within ::ffff:0:0/96 as that IPv4 network
	 * (::ffff:203.0.113.0/120 is 203.0.113.0/24). A web server listening on
	 * an IPv6 socket which takes IPv4 connections too ("[::]") may report an
	 * IPv4 client like that in REMOTE_ADDR: the client would match none of
	 * the IPv4 entries of the block or allow list otherwise. Anything else
	 * is returned as it is.
	 */
	public static function unmapped($value)
	{
		$value = (string) $value;
		$parts = explode('/', $value, 2);
		$bin = @inet_pton($parts[0]);
		if ($bin === false || strlen($bin) !== 16 || substr($bin, 0, 12) !== self::MappedPrefix)
		{
			return $value;
		}
		$ipv4 = inet_ntop(substr($bin, 12));
		if (count($parts) === 1)
		{
			return $ipv4;
		}
		if (!preg_match('/^[0-9]{1,3}\z/', $parts[1]) || (int) $parts[1] < 96 || (int) $parts[1] > 128)
		{
			return $value;
		}
		return $ipv4.'/'.((int) $parts[1] - 96);
	}

	/**
	 * The one spelling in which addresses and networks are stored in the
	 * block and allow list: an address in the compressed lower-case form of
	 * inet_ntop(), a network as its masked network address and prefix length
	 * ("2001:db8:1:2::/64", "203.0.113.0/24"); an IPv4-mapped IPv6 address
	 * or network as the IPv4 one (see unmapped()). Lookups compare these
	 * strings (see lookupCandidates()), so every writer has to use this form.
	 *
	 * @return string|null null if $value is neither an address nor a network
	 */
	public static function canonicalEntry($value)
	{
		$value = self::unmapped(trim((string) $value));
		if (!self::isValidIpOrSubnet($value))
		{
			return null;
		}
		$parts = explode('/', $value);
		$bin = inet_pton($parts[0]);
		if (count($parts) === 1)
		{
			return inet_ntop($bin);
		}
		$bits = (int) $parts[1];
		return inet_ntop($bin & self::prefixMask($bits, strlen($bin))).'/'.$bits;
	}

	/**
	 * All the entries (in canonical form) of the block or allow list which
	 * contain $ip: the address itself and its network for every prefix length.
	 * Fetching the rows whose address is one of these finds what the address is
	 * blocked or allowed by, with an index and without looking at the other
	 * entries - how many there are depends on what visitors made the plugin
	 * block, and a request from any visitor has to look.
	 *
	 * An IPv4-mapped address is looked up as the IPv4 address (see
	 * unmapped()), which is how canonicalEntry() stores it.
	 *
	 * @return string[] empty if $ip is not an address
	 */
	public static function lookupCandidates($ip)
	{
		$bin = @inet_pton(self::unmapped(trim((string) $ip)));
		if ($bin === false)
		{
			return array();
		}
		$candidates = array(inet_ntop($bin));
		for ($bits = 0; $bits <= strlen($bin) * 8; ++$bits)
		{
			$candidates[] = inet_ntop($bin & self::prefixMask($bits, strlen($bin))).'/'.$bits;
		}
		return $candidates;
	}

	/**
	 * The coarsest IPv6 network which counts as one client for *trust* (an
	 * address a user has logged in from before). Failed logins are counted
	 * per network of the configured size (a /56 by default: a client
	 * controls all of it, so coarse is right there), but a /56 may be shared
	 * by several customers of a provider, while a /64 is one network of one
	 * customer: somebody else's earlier login from the /56 says nothing
	 * about this client.
	 */
	public const TrustPrefixLength = 64;

	/**
	 * The prefix length to remember and recognise logins under, for the
	 * configured prefix length of the tracking: at least TrustPrefixLength.
	 */
	public static function trustPrefixLength($trackedPrefixLength)
	{
		return max(self::TrustPrefixLength, (int) $trackedPrefixLength);
	}

	/**
	 * The key under which failed logins and blocks of a client are tracked.
	 *
	 * For IPv4 that is the address itself. An IPv6 client usually controls a
	 * whole /64 (or more) and can switch to another address in it at will -
	 * tracking single addresses would let it start over with every request -
	 * so a global unicast IPv6 address is tracked as its network in CIDR
	 * notation (e.g. "2001:db8:1:2::/64") if $prefixLength is between 32 and
	 * 127. Left alone are IPv6 addresses that merely carry an IPv4 address or
	 * a transition mechanism's prefix (IPv4-mapped, NAT64, 6to4, Teredo):
	 * aggregating those would put unrelated clients, all over the world,
	 * under one key.
	 */
	public static function trackedAddress($ip, $prefixLength)
	{
		$prefixLength = (int) $prefixLength;
		$bin = @inet_pton((string) $ip);
		if ($bin === false || strlen($bin) !== 16 || $prefixLength < 32 || $prefixLength > 127 ||
			(ord($bin[0]) & 0xe0) !== 0x20 ||          // not 2000::/3 (global unicast)
			substr($bin, 0, 2) === "\x20\x02" ||       // 6to4, 2002::/16
			substr($bin, 0, 4) === "\x20\x01\x00\x00")  // Teredo, 2001::/32
		{
			// in the form the block list holds it in, whatever way the web
			// server spells the address (garbage is returned as it is)
			return self::canonicalEntry($ip) ?? $ip;
		}
		return inet_ntop($bin & self::prefixMask($prefixLength)).'/'.$prefixLength;
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
	 * The trusted proxies $setting (a list as parseTrustedProxies() takes
	 * it) as they are stored: separated by a comma and a space. The settings
	 * page's field is one line - a browser drops the line breaks of its
	 * value - so a list with line breaks would come back from it as one
	 * entry glued to the next.
	 */
	public static function formatTrustedProxies($setting): string
	{
		return implode(', ', self::parseTrustedProxies($setting));
	}

	/**
	 * The narrowest network which contains all of $entries (addresses and
	 * networks, at least two, of one family) - for the nodes of a proxy to
	 * be trusted as one entry; null if there is none at least as narrow as
	 * $minPrefixIPv4 or $minPrefixIPv6 (the widest network ProxylistRule
	 * takes), the families are mixed, or an entry is neither.
	 */
	public static function commonNetwork(array $entries, int $minPrefixIPv4, int $minPrefixIPv6): ?string
	{
		if (count($entries) < 2)
		{
			return null;
		}
		$first = null;
		$bits = null;
		foreach ($entries as $entry)
		{
			$network = self::network((string) $entry);
			if ($network === null || ($first !== null && strlen($network[0]) !== strlen($first)))
			{
				return null;
			}
			if ($first === null)
			{
				$first = $network[0];
				$bits = $network[1];
				continue;
			}
			$same = 0;
			while ($same < min($bits, $network[1]) && self::bit($first, $same) === self::bit($network[0], $same))
			{
				++$same;
			}
			$bits = $same;
		}
		if ($bits < (strlen($first) === 4 ? $minPrefixIPv4 : $minPrefixIPv6))
		{
			return null;
		}
		return self::canonicalEntry(inet_ntop($first).'/'.$bits);
	}

	/** The bit $i (0: the highest) of the binary address $bin. */
	private static function bit(string $bin, int $i): int
	{
		return (ord($bin[intdiv($i, 8)]) >> (7 - $i % 8)) & 1;
	}

	/**
	 * The trusted proxies of the settings, if proxy support is on
	 * (see getAddress()); empty otherwise.
	 *
	 * @return string[]
	 */
	public static function trustedProxies()
	{
		return self::proxySettings()['trustedProxies'];
	}

	private static $proxySettings = null;
	private static $proxySettingsSource = null;

	/**
	 * The proxy settings (see Settings), worked out once for the settings
	 * Joomla holds (getAddress() and trustedProxies() are called several
	 * times in a request): that they are the same object tells that they
	 * didn't change, without building a copy of them and comparing it.
	 *
	 * @return array{useProxy: bool, proxyIpAddress: string, header: string, trustedProxies: string[]}
	 */
	private static function proxySettings()
	{
		$params = Settings::held();
		if (self::$proxySettings !== null && self::$proxySettingsSource === $params)
		{
			return self::$proxySettings;
		}
		$settings = array('useProxy' => false, 'proxyIpAddress' => '',
			'header' => 'HTTP_X_FORWARDED_FOR', 'trustedProxies' => array());
		$settings['useProxy'] = Settings::bool($params, 'useProxy');
		$settings['proxyIpAddress'] = Settings::string($params, 'proxyIpAddress');
		$settings['header'] = Settings::string($params, 'proxyHeaderSource');
		if ($settings['useProxy'])
		{
			$settings['trustedProxies'] = self::parseTrustedProxies($settings['proxyIpAddress']);
		}
		self::$proxySettings = $settings;
		self::$proxySettingsSource = $params;
		self::$address = null;
		return $settings;
	}

	/**
	 * An address or network as its binary network address and prefix length,
	 * null if it is neither.
	 */
	private static function network($value)
	{
		$canonical = self::canonicalEntry($value);
		if ($canonical === null)
		{
			return null;
		}
		$parts = explode('/', $canonical);
		$bin = inet_pton($parts[0]);
		return array($bin, count($parts) === 2 ? (int) $parts[1] : strlen($bin) * 8);
	}

	/**
	 * The prefix length of an address or network: 32 or 128 for an address,
	 * null if $value is neither.
	 */
	public static function prefixLength($value)
	{
		$network = self::network($value);
		return $network === null ? null : $network[1];
	}

	/**
	 * Whether the address or network $inner is within the network $outer
	 * (or is $outer). Malformed entries contain nothing and are in nothing.
	 */
	public static function contains($outer, $inner)
	{
		$outerNetwork = self::network($outer);
		$innerNetwork = self::network($inner);
		if ($outerNetwork === null || $innerNetwork === null ||
			strlen($outerNetwork[0]) !== strlen($innerNetwork[0]) || $innerNetwork[1] < $outerNetwork[1])
		{
			return false;
		}
		$mask = self::prefixMask($outerNetwork[1], strlen($outerNetwork[0]));
		return ($outerNetwork[0] & $mask) === ($innerNetwork[0] & $mask);
	}

	/**
	 * The entries of $list (addresses or networks) which overlap the address
	 * or network $entry: contain it, are contained in it, or are the same.
	 * Malformed entries never overlap.
	 *
	 * @return string[]
	 */
	public static function overlapping($entry, array $list)
	{
		$network = self::network($entry);
		if ($network === null)
		{
			return array();
		}
		$result = array();
		foreach ($list as $other)
		{
			$otherNetwork = self::network($other);
			if ($otherNetwork === null || strlen($otherNetwork[0]) !== strlen($network[0]))
			{
				continue;
			}
			$mask = self::prefixMask(min($network[1], $otherNetwork[1]), strlen($network[0]));
			if (($network[0] & $mask) === ($otherNetwork[0] & $mask))
			{
				$result[] = $other;
			}
		}
		return $result;
	}

	/**
	 * Whether the address or network $entry contains one of the
	 * $trustedProxies (addresses or networks) or part of one of them.
	 *
	 * With proxy support on, a failed login whose forwarding header can't be
	 * read is counted against the address the request came from: a trusted
	 * proxy (see getAddress()). Not counting it would let whoever can send
	 * such a request fail logins without limit; blocking the proxy only
	 * holds back the requests which resolve to its address - except in the
	 * .htaccess file, where the web server knows nothing of the header and
	 * would turn away every request coming through the proxy.
	 */
	public static function overlapsTrustedProxy($entry, array $trustedProxies)
	{
		return count(self::overlapping($entry, $trustedProxies)) > 0;
	}

	/**
	 * Whether $ip is one of the $trustedProxies (see parseTrustedProxies()).
	 * Addresses are compared in binary form, so different spellings of the
	 * same IPv6 address match.
	 */
	public static function isTrustedProxy($ip, array $trustedProxies)
	{
		// an IPv4-mapped address is the IPv4 address, see unmapped()
		$ipBin = @inet_pton(self::unmapped($ip));
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
			elseif (@inet_pton(self::unmapped($proxy)) === $ipBin)
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
	 *
	 * CF-Connecting-IP (CloudflareHeader) is the exception: it holds one
	 * address, which counts only if it is exactly one valid address.
	 */
	public static function clientAddressFromHeader($headerName, $headerValue, array $trustedProxies)
	{
		if ($headerName === self::CloudflareHeader)
		{
			// one address, which Cloudflare wrote itself: a list, a port or
			// anything else is not what Cloudflare sends
			$value = trim((string) $headerValue);
			return filter_var($value, FILTER_VALIDATE_IP) !== false ? self::unmapped($value) : null;
		}
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
				return self::unmapped($addresses[$i]);
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
		// an IPv4 client of a server listening on an IPv6 socket may come
		// as ::ffff:203.0.113.5: as the IPv4 address, see unmapped()
		$remoteAddr = self::unmapped(array_key_exists('REMOTE_ADDR', $_SERVER) ? $_SERVER['REMOTE_ADDR'] : '');

		$settings = self::proxySettings();
		if (!$settings['useProxy'])
		{
			return $remoteAddr;
		}
		// the plugin asks for it in several events of a request, the
		// component again: worked out (and warned about) once for what it
		// depends on
		$header = $_SERVER[$settings['header']] ?? null;
		if (self::$address !== null && self::$address['remote'] === $remoteAddr && self::$address['header'] === $header)
		{
			return self::$address['client'];
		}
		$client = self::addressBehindProxy($remoteAddr, $settings, $logger);
		self::$address = array('remote' => $remoteAddr, 'header' => $header, 'client' => $client);
		return $client;
	}

	// what getAddress() found last behind a proxy, for the settings
	// proxySettings() holds: its REMOTE_ADDR, header and the client address
	private static $address = null;

	// a request which bypassed the proxy is warned about once in this many
	// seconds for its address (or the others of its slot)
	public const DirectRequestWarningInterval = 3600;
	private const DirectRequestWarningSlots = 64;

	/**
	 * The stamp file of the warning about a request from $remoteAddr which
	 * did not come through the proxy (see mayWarnAboutDirectRequest()).
	 */
	public static function directRequestWarningFile($remoteAddr): string
	{
		return LockHelper::file('proxywarning',
			LockHelper::slot($remoteAddr, self::DirectRequestWarningSlots), 'stamp');
	}

	/**
	 * Whether a request from $remoteAddr which did not come through the
	 * proxy is to be logged. Every such request would otherwise write a
	 * warning - anybody can send them, as many as they like, and push the
	 * entries that matter out of the rotated log - so it is once an hour for
	 * each address; addresses are spread over a fixed number of stamp files,
	 * so that many addresses can't fill the temporary directory either.
	 */
	private static function mayWarnAboutDirectRequest($remoteAddr): bool
	{
		return LockHelper::due(self::directRequestWarningFile($remoteAddr), self::DirectRequestWarningInterval);
	}

	/**
	 * The client address of a request which came through a proxy, if
	 * REMOTE_ADDR is one of the trusted ones, see getAddress().
	 */
	private static function addressBehindProxy($remoteAddr, array $settings, LoggerHelper $logger)
	{
		$proxyIpAddress = $settings['proxyIpAddress'];
		$trustedProxies = $settings['trustedProxies'];
		if (count($trustedProxies) === 0 || !self::isTrustedProxy($remoteAddr, $trustedProxies))
		{
			if (!self::mayWarnAboutDirectRequest($remoteAddr))
			{
				return $remoteAddr;
			}
			$logger->log('Proxy/load balancer usage is enabled, but the request did not originate from the '.
				'configured proxy IP address (configured: "'.$proxyIpAddress.'", actual: "'.$remoteAddr.
				'") - ignoring the proxy header and using REMOTE_ADDR!', Log::WARNING);
			return $remoteAddr;
		}

		$proxyHeaderSource = $settings['header'];
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
