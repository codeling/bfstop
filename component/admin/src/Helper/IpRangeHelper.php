<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\IpHelper;

class IpRangeHelper
{
	public static function isIPv6($ip)
	{
		return str_contains($ip, ':');
	}

	public static function numOfAddresses($cidr)
	{
		$cidrParts = explode('/', $cidr);
		$addressBits = self::isIPv6($cidrParts[0]) ? 128 : 32;
		return pow(2, $addressBits - (int) $cidrParts[1]);
	}

	// numOfAddresses() returns a float once the count exceeds PHP's native
	// int range (any IPv6 /64 or wider already does) - format it without
	// scientific notation for display
	public static function formatCount($count)
	{
		return is_float($count) ? sprintf('%.0f', $count) : (string) $count;
	}

	/**
	 * The first and the last address of the network $cidr ("192.0.2.77/24"
	 * gives 192.0.2.0 and 192.0.2.255), for IPv4 and IPv6 alike.
	 *
	 * @return string[] array(first, last)
	 */
	public static function cidrToRange($cidr)
	{
		$cidrParts = explode('/', $cidr);
		$bin = @inet_pton($cidrParts[0]);
		if ($bin === false || count($cidrParts) !== 2)
		{
			// an entry which is no network (typed by hand into the table)
			return array('', '');
		}
		$mask = IpHelper::prefixMask((int) $cidrParts[1], strlen($bin));
		$first = $bin & $mask;
		return array(inet_ntop($first), inet_ntop($first | ($mask ^ str_repeat("\xff", strlen($bin)))));
	}
}
