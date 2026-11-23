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

/**
 * Whether the administrator's own request fits the saved proxy settings: a
 * proxy which appeared, was removed or changed its address or header, a
 * web server which now resolves the address itself. Hosting changes and
 * nobody tells BFStop - and wrong proxy settings block every visitor, or let
 * attackers choose their address. There is no other change detection (no
 * sampling of visitors' requests): this looks at $_SERVER and the settings
 * Joomla holds, and the dismissed mismatches of the setup state (one query,
 * by whoever shows the result - the quick icon and the banner of the BFStop
 * backend).
 *
 * Every mismatch has a fingerprint, of what it is and of the request's
 * headers and kind of address (never the address itself): an administrator
 * who reaches the backend another way (a VPN, the internal network) says
 * "this is expected" once, and a different mismatch shows again.
 */
final class ProxyMismatch
{
	// the saved settings trust no proxy, the request carries a forwarding
	// header from a non-public address, or CF-Connecting-IP
	public const AppearsBehindProxy = 'appearsBehindProxy';
	// a proxy is trusted; the request has a header, but isn't from one of them
	public const ProxyAddressChanged = 'proxyAddressChanged';
	// a proxy is trusted; the request has no header and isn't from one of them
	public const ProxyRemoved = 'proxyRemoved';
	// from a trusted proxy, without the configured header but with another one
	public const HeaderChanged = 'headerChanged';
	// a proxy is trusted; the request is from the public address its header ends in
	public const ServerResolves = 'serverResolves';
	// only headers BFStop doesn't read
	public const UnsupportedHeader = 'unsupportedHeader';
	// Joomla's "Behind Load Balancer" doesn't fit (see ProxyDetector::loadBalancerHint())
	public const LoadBalancer = 'loadBalancer';

	/** the mismatches which are information only: they don't make the quick icon a warning */
	public const InformationOnly = array(self::LoadBalancer);

	/**
	 * The mismatches between the request $server and the proxy settings
	 * $proxy (see ProxyDetector::proxySettings()).
	 *
	 * @param SetupState|null $state the dismissed ones are marked
	 * @return array[] each: code, fingerprint, dismissed (bool), information
	 *                 (bool, see InformationOnly), detected (what
	 *                 ProxyDetector::detect() found), hint (for LoadBalancer:
	 *                 switchOn or switchOff)
	 */
	public static function check(array $server, array $proxy, bool $behindLoadBalancer, ?SetupState $state = null): array
	{
		$detected = ProxyDetector::detect($server, $proxy, $behindLoadBalancer);
		$codes = array();
		if (count($detected['supported']) === 0 && count($detected['unsupported']) > 0)
		{
			$codes[] = self::UnsupportedHeader;
		}
		if (!$proxy['useProxy'])
		{
			if (count($detected['supported']) > 0 && ($detected['remoteNonPublic'] || $detected['cloudflare']))
			{
				$codes[] = self::AppearsBehindProxy;
			}
		}
		elseif (!$detected['fromTrusted'])
		{
			if (count($detected['supported']) === 0)
			{
				$codes[] = self::ProxyRemoved;
			}
			else
			{
				$configured = $proxy['header'];
				$header = isset($detected['supported'][$configured]) ? $configured : $detected['header'];
				$last = IpHelper::lastHeaderAddress($header, $detected['supported'][$header]);
				$codes[] = (!$detected['remoteNonPublic'] && $last !== null &&
					IpHelper::canonicalEntry($last) === IpHelper::canonicalEntry($detected['remote']))
					? self::ServerResolves : self::ProxyAddressChanged;
			}
		}
		elseif (!isset($detected['supported'][$proxy['header']]) &&
			count($detected['supported']) > 0)
		{
			$codes[] = self::HeaderChanged;
		}
		$hint = ProxyDetector::loadBalancerHint($proxy['useProxy'], $detected['scenario'], $behindLoadBalancer);
		if ($hint !== null)
		{
			$codes[] = self::LoadBalancer;
		}
		$mismatches = array();
		foreach ($codes as $code)
		{
			$fingerprint = self::fingerprint($code, $detected, $hint);
			$mismatches[] = array(
				'code' => $code,
				'fingerprint' => $fingerprint,
				'dismissed' => $state !== null && $state->isDismissed($fingerprint),
				'information' => in_array($code, self::InformationOnly, true),
				'detected' => $detected,
				'hint' => $code === self::LoadBalancer ? $hint : null,
			);
		}
		return $mismatches;
	}

	/**
	 * The mismatches of check() which are neither dismissed nor (with
	 * $warningsOnly) information only.
	 */
	public static function open(array $mismatches, bool $warningsOnly = false): array
	{
		return array_values(array_filter($mismatches, fn ($mismatch) => !$mismatch['dismissed'] &&
			!($warningsOnly && $mismatch['information'])));
	}

	/**
	 * The fingerprint of the mismatch $code of a request: what it is, the
	 * headers the request carried and whether its address is a public one.
	 */
	private static function fingerprint(string $code, array $detected, ?string $hint): string
	{
		$headers = array_merge(array_keys($detected['supported']), array_keys($detected['unsupported']));
		sort($headers);
		return substr(sha1($code.'|'.implode(',', $headers).'|'.($detected['remoteNonPublic'] ? 'private' : 'public').
			'|'.(string) $hint), 0, 12);
	}
}
