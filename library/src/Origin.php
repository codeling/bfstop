<?php
/*
 * @package BFStop Library (lib_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop;

defined('_JEXEC') or die;

use Joomla\CMS\Application\CMSApplicationInterface;

/**
 * The parts of Joomla a request or a failed login comes from, and the
 * "enabledForOrigin" setting, a bitmask of the parts Brute Force Stop is
 * active for. Joomla's other applications - the installation (client id 2)
 * and the console (cli/joomla.php, client 4) - have no logins and no bit.
 */
final class Origin
{
	public const Frontend = 1;
	public const Backend = 2;
	public const Api = 4;

	/** the bit of each application, by its name */
	private const Clients = array(
		'site' => self::Frontend,
		'administrator' => self::Backend,
		'api' => self::Api,
	);

	/**
	 * The name of the application of a request, as the log and mails show it:
	 * the client id site 0, administrator 1, api 3.
	 */
	public static function name($clientId)
	{
		switch ((int) $clientId)
		{
			case 0:
				return 'Frontend';
			case 3:
				return 'API';
			default:
				return 'Backend';
		}
	}

	/**
	 * The "enabledForOrigin" setting as the bitmask it is stored as, also
	 * from the list of bits the settings form has a checkbox for each (see
	 * com_bfstop's SettingsModel); other bits are dropped.
	 */
	public static function mask($value)
	{
		$mask = 0;
		foreach (is_array($value) ? $value : array($value) as $bits)
		{
			$mask |= is_numeric($bits) ? (int) $bits : 0;
		}
		return $mask & array_sum(self::Clients);
	}

	/**
	 * The bits set in an "enabledForOrigin" bitmask, as the settings form's
	 * checkboxes take them (strings, in the order of the constants).
	 */
	public static function list($mask)
	{
		$mask = self::mask($mask);
		$list = array();
		foreach (self::Clients as $bit)
		{
			if ($mask & $bit)
			{
				$list[] = (string) $bit;
			}
		}
		return $list;
	}

	/**
	 * Whether the "enabledForOrigin" setting $setting has the bit of the
	 * application $app. By the application's name, not its client id:
	 * getClientId() + 1 gave the bits only by luck (site 0, administrator 1,
	 * api 3), the installation (2) and the console (4, which hasn't even got
	 * the method) would come out as other parts' bits.
	 */
	public static function isEnabled($setting, CMSApplicationInterface $app)
	{
		$enabledFor = self::mask($setting);
		foreach (self::Clients as $client => $bit)
		{
			if ($app->isClient($client))
			{
				return ($enabledFor & $bit) !== 0;
			}
		}
		return false;
	}
}
