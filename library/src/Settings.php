<?php
/*
 * @package BFStop Library (lib_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop;

defined('_JEXEC') or die;

/**
 * The settings of Brute Force Stop: what they are while they have not been
 * saved. They are edited on the settings page of the component
 * (com_bfstop's forms/settings.xml, whose defaults a test compares with
 * these).
 */
final class Settings
{
	/**
	 * What the settings are while they have not been saved: the same as the
	 * settings page shows for them. The plugin is enabled by the
	 * installation, so it runs with these until an administrator opens the
	 * settings.
	 */
	public const Defaults = array(
		'blockNumber' => 10,
		'checkInterval' => 10080,
		'maxBlocksBefore' => 3,
		'notifyUsePasswordReminder' => 1,
		'adaptiveDelayMax' => 0,
		'adaptiveDelayThresholdMin' => 50,
		'adaptiveDelayThresholdMax' => 200,
		// failed logins are purged after this many weeks unless the
		// administrator chose another time (0 = never). Keeping them for ever
		// is not needed to protect anything, and they are personal data
		// (addresses, usernames)
		'deleteOld' => 4,
		'logLevel' => 8, // Log::ERROR
		'riskCommonUsernames' => "admin\nadministrator\nroot\ntest\nwebmaster",
		// frontend, backend and the Web Services API
		'enabledForOrigin' => Origin::Frontend | Origin::Backend | Origin::Api,
		// a delay ties up a PHP worker for its whole length, see the
		// plugin's Responder::delay(): the risk score adds none unless the
		// administrator asks for it
		'riskDelaySecondsPerPoint' => 0,
		// what an IPv6 client is tracked by, see IpHelper::trackedAddress():
		// a connection usually gets a /56 (or more), not just a /64, so a /64
		// would let a client start over 256 times
		'ipv6PrefixLength' => 56,
		// at most this many responses are delayed at the same time
		'delayMaxConcurrent' => 5,
	);
}
