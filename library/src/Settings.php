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
	 * A setting of $params (the settings, see stored() and held()): what is
	 * stored, or its default (Defaults) if nothing - or an empty string - is.
	 * Every setting is read this way, so that its default is in one place.
	 *
	 * @throws \InvalidArgumentException for a name which is no setting
	 */
	public static function get(Registry $params, string $name)
	{
		if (!array_key_exists($name, self::Defaults))
		{
			throw new \InvalidArgumentException("There is no setting '$name'");
		}
		return $params->get($name, self::Defaults[$name]);
	}

	/** A setting as a number, see get(). */
	public static function int(Registry $params, string $name): int
	{
		return (int) self::get($params, $name);
	}

	/** A setting which is switched on or off, see get(). */
	public static function bool(Registry $params, string $name): bool
	{
		return (bool) self::get($params, $name);
	}

	/** A setting as a string, see get(). */
	public static function string(Registry $params, string $name): string
	{
		return (string) self::get($params, $name);
	}

	/**
	 * What the settings are while they have not been saved: the same as the
	 * settings page shows for them (forms/settings.xml, which a test compares
	 * with this, both ways). The setup assistant, which activates the
	 * plugin, saves the settings with the values the settings page shows, so
	 * these are what an installation starts with.
	 */
	public const Defaults = array(
		// basic
		'blockMode' => 'full',
		'blockNumber' => 10,
		'blockDuration' => 1440,
		// notifications
		'emailaddress' => '',
		// no user or group chosen
		'userID' => '',
		'groupNotificationEnabled' => 0,
		'userGroup' => '',
		'notifyBlockedUser' => 0,
		'notifyBlockedNumber' => 5,
		'notifyFailedNumber' => 0,
		'notifyFailedOnlyExisting' => 0,
		// proxy
		'useProxy' => 0,
		'proxyHeaderSource' => 'HTTP_X_FORWARDED_FOR',
		'proxyIpAddress' => '',
		// advanced
		// frontend, backend and the Web Services API
		'enabledForOrigin' => Origin::Frontend | Origin::Backend | Origin::Api,
		'progressiveBlockDuration' => 0,
		'maxBlocksBefore' => 3,
		'checkInterval' => 10080,
		'notifyRemainingAttempts' => 0,
		'notifyUsePasswordReminder' => 1,
		// empty: the message of the language file
		'blockedMessage' => '',
		'blockedMsgShowIP' => 0,
		'logLevel' => 8, // Log::ERROR
		'logMaxSize' => 5,
		'logKeepDays' => 28,
		'unknownUsernameMode' => 'hash',
		// what an IPv6 client is tracked by, see IpHelper::trackedAddress():
		// a connection usually gets a /56 (or more), not just a /64, so a /64
		// would let a client start over 256 times
		'ipv6PrefixLength' => 56,
		'useHttpError' => 1,
		// failed logins are purged after this many weeks unless the
		// administrator chose another time (0 = never). Keeping them for ever
		// is not needed to protect anything, and they are personal data
		// (addresses, usernames)
		'deleteOld' => 4,
		// empty: the root of the site
		'htaccessPath' => '',
		'nginxDenyFile' => '',
		// distributed attacks on one account: a signal of the risk score,
		// see RiskHelper::accountAttackScore()
		'accountAttackEnabled' => 1,
		'accountBlockNumber' => 20,
		'accountCheckInterval' => 60,
		'accountAttackPoints' => 3,
		// GeoIP
		'geoDbPath' => '',
		// risk score
		'riskGeoEnabled' => 0,
		'riskGeoHomeCountries' => '',
		'riskGeoPoints' => 3,
		'riskReverseDnsEnabled' => 0,
		'riskReverseDnsPoints' => 2,
		'riskKnownIpEnabled' => 1,
		'riskKnownIpPoints' => 5,
		'riskCommonUsernameEnabled' => 1,
		'riskCommonUsernames' => "admin\nadministrator\nroot\ntest\nwebmaster",
		'riskCommonUsernamePoints' => 2,
		'riskUserAgentEnabled' => 1,
		'riskUserAgentPoints' => 2,
		'riskBlockNumberReductionPerPoint' => 1,
		'riskMinBlockNumber' => 2,
	);
}
