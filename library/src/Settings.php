<?php
/*
 * @package BFStop Library (lib_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop;

defined('_JEXEC') or die;

use Joomla\CMS\Component\ComponentHelper;
use Joomla\Registry\Registry;

/**
 * The settings of Brute Force Stop. They are the component's: the params of
 * com_bfstop's row of Joomla's extensions table, edited on its settings page
 * (forms/settings.xml, whose defaults a test compares with Defaults below).
 * Until 2.0.0, they were the system plugin's params; its update moves them
 * (see the plugin's updatescript.php).
 */
final class Settings
{
	/** the extension whose params the settings are */
	public const Extension = 'com_bfstop';

	/**
	 * The settings as they are stored (an empty Registry while they have not
	 * been saved, or if the component is not installed or is disabled: the
	 * defaults apply then). Joomla has the params of all components loaded
	 * anyway, so this costs no query; a copy, which the caller may change.
	 */
	public static function stored(): Registry
	{
		return new Registry(ComponentHelper::getParams(self::Extension)->toArray());
	}

	/**
	 * The settings as Joomla holds them for the request, not a copy: to be
	 * read only. It is the same object until Joomla loads them again, so
	 * whoever keeps what it works out from them can tell by the object
	 * whether that is still up to date, without comparing the settings
	 * (see IpHelper::getAddress()). While the component isn't installed,
	 * each call gives a new, empty one.
	 */
	public static function held(): Registry
	{
		return ComponentHelper::getParams(self::Extension);
	}

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
