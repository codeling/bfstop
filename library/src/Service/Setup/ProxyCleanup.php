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
use Codeling\Library\Bfstop\Repository\BlockRepository;
use Codeling\Library\Bfstop\Repository\Repositories;

/**
 * What a site behind a proxy collected while BFStop took the proxy's
 * address for every visitor's (between the update and the proxy step):
 * blocks of the proxy - which block everybody -, the failed logins counted
 * against it, its earlier blocks remembered by the purge (which make the
 * next block permanent), the "known addresses" every user got from it
 * (which waive the unblock mail's check), and entries of the allow list
 * which contain a proxy (a common workaround, which exempts every visitor).
 * The setup assistant's clean-up step shows them and, when the
 * administrator confirms, removes all but the allow list's entries, which
 * are the administrator's to change.
 */
final class ProxyCleanup
{
	private Repositories $repositories;

	public function __construct(Repositories $repositories)
	{
		$this->repositories = $repositories;
	}

	/** The entries of $candidates which overlap one of the $trusted proxies. */
	private static function ofProxies(array $candidates, array $trusted): array
	{
		return array_values(array_filter($candidates, fn ($entry) => IpHelper::overlapsTrustedProxy((string) $entry, $trusted)));
	}

	/**
	 * What there is of the trusted proxies $trusted (addresses and networks).
	 *
	 * @return array{blocks: string[], blockIds: int[], failedLogins: array<string, int>, offences: string[],
	 *               knownIps: string[], allowList: string[]}
	 *         blocks: the active blocks' entries, failedLogins: entry => number
	 */
	public function findings(array $trusted): array
	{
		$blocks = self::ofProxies($this->repositories->blocks()->activeAddresses() ?? array(), $trusted);
		$failedLogins = array();
		foreach ($this->repositories->failedLogins()->countsByAddress() as $address => $count)
		{
			if (IpHelper::overlapsTrustedProxy($address, $trusted))
			{
				$failedLogins[$address] = $count;
			}
		}
		$allowList = array();
		foreach ($trusted as $proxy)
		{
			$allowList = array_merge($allowList, $this->repositories->allowList()->entriesOverlapping($proxy) ?? array());
		}
		return array(
			'blocks' => $blocks,
			'blockIds' => $this->repositories->blocks()->activeIdsOfEntries($blocks) ?? array(),
			'failedLogins' => $failedLogins,
			'offences' => self::ofProxies($this->repositories->blocks()->offenceAddresses(), $trusted),
			'knownIps' => self::ofProxies($this->repositories->knownIps()->addresses(), $trusted),
			'allowList' => array_values(array_unique($allowList)),
		);
	}

	/** Whether findings() found anything. */
	public static function anything(array $findings): bool
	{
		return count($findings['blocks']) + count($findings['failedLogins']) + count($findings['offences']) +
			count($findings['knownIps']) + count($findings['allowList']) > 0;
	}

	/**
	 * Lifts the blocks of the proxies, deletes the failed logins counted
	 * against them, forgets their offences and the logins remembered from
	 * them - what findings() found for $trusted; the allow list stays.
	 *
	 * @return array the findings which were removed
	 */
	public function clean(array $trusted): array
	{
		$findings = $this->findings($trusted);
		if (count($findings['blockIds']) > 0)
		{
			$this->repositories->blocks()->lift($findings['blockIds'], BlockRepository::LiftedByAdministrator);
		}
		$this->repositories->failedLogins()->deleteFromAddresses(array_keys($findings['failedLogins']));
		$this->repositories->blocks()->forgetOffences($findings['offences']);
		$this->repositories->knownIps()->forgetAddresses($findings['knownIps']);
		return $findings;
	}

	/**
	 * The active blocks which look like a proxy's while BFStop trusts none
	 * (or other ones): blocks of non-public addresses, and of the address
	 * $remote the administrator's request came from - signals of the
	 * proxy step.
	 *
	 * @return string[]
	 */
	public function suspiciousBlocks(string $remote): array
	{
		$remoteKey = IpHelper::canonicalEntry($remote);
		return array_values(array_filter($this->repositories->blocks()->activeAddresses() ?? array(),
			fn ($entry) => IpHelper::isNonPublic(explode('/', (string) $entry)[0]) ||
				($remoteKey !== null && IpHelper::contains((string) $entry, $remoteKey))));
	}
}
