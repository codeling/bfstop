<?php
/*
 * @package BFStop Library (lib_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Service\Setup;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Settings;
use Joomla\Registry\Registry;

/**
 * How the site is reached, as far as the administrator's own request tells:
 * directly, through a proxy, load balancer or CDN, or through one whose
 * header BFStop can't read. A function of $_SERVER, the settings and
 * Joomla's "Behind Load Balancer" only, so that the scenarios can be tested
 * without a site:
 *
 * - A: no forwarding header - the site is reached directly
 * - B: a forwarding header, from a non-public address - a reverse proxy or
 *   load balancer next to the web server
 * - C: a forwarding header whose last entry is the public address the request
 *   came from - the web server already resolves the address (mod_remoteip,
 *   nginx's real_ip), BFStop's proxy setting must stay off
 * - D: a forwarding header, from another public address - a CDN (or a proxy
 *   of the administrator's own, which adds the header on the way out)
 * - E: only headers BFStop doesn't read (IpHelper::UnsupportedProxyHeaders)
 *
 * The plugin's installer script makes the same distinction without this
 * class, to disable the plugin during an update; a test checks that both
 * agree.
 */
final class ProxyDetector
{
	public const Direct = 'A';
	public const BehindProxy = 'B';
	public const ServerResolves = 'C';
	public const BehindCdn = 'D';
	public const Unsupported = 'E';

	/**
	 * The headers proposed for a proxy, the first one present: Forwarded is
	 * standardised (RFC 7239), X-Forwarded-For the most common;
	 * CF-Connecting-IP is Cloudflare's. Then the others BFStop reads.
	 */
	private const HeaderPreference = array('HTTP_FORWARDED', 'HTTP_X_FORWARDED_FOR', IpHelper::CloudflareHeader);

	/**
	 * What the request $server tells about how the site is reached.
	 *
	 * @param array $server             $_SERVER of the request
	 * @param array $proxy              the proxy settings (see proxySettings())
	 * @param bool  $behindLoadBalancer Joomla's "Behind Load Balancer"
	 * @return array{scenario: string, remote: string, remoteNonPublic: bool,
	 *               supported: array<string, string>, unsupported: array<string, string>,
	 *               header: string|null, last: string|null, cloudflare: bool,
	 *               behindLoadBalancer: bool, fromTrusted: bool}
	 *         supported: the forwarding headers BFStop reads which the request
	 *         carried ($_SERVER key => value), unsupported: those it doesn't
	 *         ($_SERVER key => name); header: the one to propose for a proxy,
	 *         last: its last entry; fromTrusted: whether the request came from
	 *         a trusted proxy of the settings
	 */
	public static function detect(array $server, array $proxy, bool $behindLoadBalancer): array
	{
		$remote = IpHelper::unmapped(trim((string) ($server['REMOTE_ADDR'] ?? '')));
		$supported = array();
		foreach (IpHelper::KnownProxyHeaders as $key)
		{
			if (isset($server[$key]) && trim((string) $server[$key]) !== '')
			{
				$supported[$key] = (string) $server[$key];
			}
		}
		$unsupported = array();
		foreach (IpHelper::UnsupportedProxyHeaders as $key => $name)
		{
			if (isset($server[$key]) && trim((string) $server[$key]) !== '')
			{
				$unsupported[$key] = $name;
			}
		}
		$header = null;
		foreach (array_merge(self::HeaderPreference, IpHelper::KnownProxyHeaders) as $key)
		{
			if (isset($supported[$key]))
			{
				$header = $key;
				break;
			}
		}
		$last = $header !== null ? IpHelper::lastHeaderAddress($header, $supported[$header]) : null;
		$remoteNonPublic = IpHelper::isNonPublic($remote);
		$trusted = $proxy['useProxy'] ? $proxy['trusted'] : array();
		return array(
			'scenario' => self::scenario($remote, $remoteNonPublic, $header !== null, count($unsupported) > 0, $last),
			'remote' => $remote,
			'remoteNonPublic' => $remoteNonPublic,
			'supported' => $supported,
			'unsupported' => $unsupported,
			'header' => $header,
			'last' => $last,
			'cloudflare' => isset($supported[IpHelper::CloudflareHeader]),
			'behindLoadBalancer' => $behindLoadBalancer,
			'fromTrusted' => count($trusted) > 0 && IpHelper::isTrustedProxy($remote, $trusted),
		);
	}

	/**
	 * The proxy settings of the settings $settings (see Settings), as the
	 * functions of this class and ProxyMismatch take them: whether a proxy
	 * is trusted, its header, the trusted proxies.
	 *
	 * @return array{useProxy: bool, header: string, trusted: string[]}
	 */
	public static function proxySettings(Registry $settings): array
	{
		return array(
			'useProxy' => Settings::bool($settings, 'useProxy'),
			'header' => Settings::string($settings, 'proxyHeaderSource'),
			'trusted' => IpHelper::parseTrustedProxies(Settings::string($settings, 'proxyIpAddress')),
		);
	}

	/**
	 * The scenario (see the class) of a request from $remote, with or without
	 * a forwarding header BFStop reads (whose last entry is $last) and one it
	 * doesn't.
	 */
	public static function scenario(string $remote, bool $remoteNonPublic, bool $supported, bool $unsupported,
		?string $last): string
	{
		if (!$supported)
		{
			return $unsupported ? self::Unsupported : self::Direct;
		}
		if (!$remoteNonPublic && $last !== null && IpHelper::canonicalEntry($last) === IpHelper::canonicalEntry($remote))
		{
			return self::ServerResolves;
		}
		return $remoteNonPublic ? self::BehindProxy : self::BehindCdn;
	}

	/** Whether the plugin would block the proxy (everybody) in scenario $scenario without proxy settings. */
	public static function needsProxySettings(string $scenario): bool
	{
		return in_array($scenario, array(self::BehindProxy, self::BehindCdn, self::Unsupported), true);
	}

	/**
	 * The proxy settings to propose for what detect() found ($detected):
	 * useProxy, proxyHeaderSource and proxyIpAddress. Behind a proxy, the
	 * address the request came from is the one to trust, and the header the
	 * one present (see HeaderPreference); for Cloudflare, its address ranges
	 * have to be fetched (see the setup assistant). Otherwise none.
	 */
	public static function proposal(array $detected): array
	{
		if (!in_array($detected['scenario'], array(self::BehindProxy, self::BehindCdn), true) || $detected['header'] === null)
		{
			return array('useProxy' => 0);
		}
		return array(
			'useProxy' => 1,
			'proxyHeaderSource' => $detected['header'],
			'proxyIpAddress' => IpHelper::canonicalEntry($detected['remote']) ?? '',
		);
	}

	/**
	 * The client address BFStop would take for the request $server with the
	 * proxy settings $useProxy, $header and $trusted (a list as the setting
	 * holds it) - what IpHelper::getAddress() does, for settings not saved
	 * yet: the dry run the administrator checks before they are saved.
	 *
	 * @return array{address: string, problem: string|null} problem: why the
	 *         address is the one the request came from: 'notTrusted' (it is
	 *         none of the trusted proxies), 'noHeader' (the header is
	 *         missing), 'unusable' (it doesn't end in an address which isn't
	 *         a trusted proxy); null if the address is the header's
	 */
	public static function preview(array $server, bool $useProxy, string $header, string $trusted): array
	{
		$remote = IpHelper::unmapped(trim((string) ($server['REMOTE_ADDR'] ?? '')));
		if (!$useProxy)
		{
			return array('address' => $remote, 'problem' => null);
		}
		$proxies = IpHelper::parseTrustedProxies($trusted);
		if (count($proxies) === 0 || !IpHelper::isTrustedProxy($remote, $proxies))
		{
			return array('address' => $remote, 'problem' => 'notTrusted');
		}
		if (!isset($server[$header]) || trim((string) $server[$header]) === '')
		{
			return array('address' => $remote, 'problem' => 'noHeader');
		}
		$client = IpHelper::clientAddressFromHeader($header, $server[$header], $proxies);
		return $client === null
			? array('address' => $remote, 'problem' => 'unusable')
			: array('address' => $client, 'problem' => null);
	}

	/**
	 * The fingerprint of a proxy setup: the scenario, the header and whether
	 * the request came from a trusted proxy - what the administrator
	 * confirmed, without an address.
	 */
	public static function fingerprint(string $scenario, ?string $header, bool $fromTrusted): string
	{
		return substr(sha1($scenario.'|'.(string) $header.'|'.($fromTrusted ? '1' : '0')), 0, 12);
	}

	/**
	 * The hint about Joomla's "Behind Load Balancer" for BFStop's proxy
	 * setting $useProxy and the scenario $scenario: null if it fits (or the scenario
	 * says nothing about it), 'switchOn' if BFStop trusts a proxy but Joomla
	 * doesn't know it is behind one (its sessions and logs, BFStop's entries
	 * in the User Actions Log too, have the proxy's address), 'switchOff' if
	 * Joomla takes the address from a header which nothing makes
	 * trustworthy. Information only: BFStop doesn't use Joomla's setting.
	 */
	public static function loadBalancerHint(bool $useProxy, ?string $scenario, bool $behindLoadBalancer): ?string
	{
		if ($useProxy && !$behindLoadBalancer)
		{
			return 'switchOn';
		}
		if (!$useProxy && $behindLoadBalancer &&
			in_array($scenario, array(null, self::Direct, self::ServerResolves), true))
		{
			return 'switchOff';
		}
		return null;
	}
}
