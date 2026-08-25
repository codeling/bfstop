<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

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

	// builds a $bits-long run of 1-bits (from the most significant bit),
	// packed into a 16-byte binary string, for use as an IPv6 netmask
	public static function ipv6Mask($bits)
	{
		$fullBytes = intdiv($bits, 8);
		$mask = str_repeat("\xff", $fullBytes);
		$remainderBits = $bits % 8;
		if ($remainderBits > 0)
		{
			$mask .= chr((0xff << (8 - $remainderBits)) & 0xff);
		}
		return str_pad($mask, 16, "\x00");
	}

	private static function cidrToRangeIPv6($cidrParts)
	{
		$startBin = inet_pton($cidrParts[0]);
		$mask = self::ipv6Mask((int) $cidrParts[1]);
		$invertedMask = $mask ^ str_repeat("\xff", 16);
		$startBin &= $mask;
		$endBin = $startBin | $invertedMask;
		return array(inet_ntop($startBin), inet_ntop($endBin));
	}

	private static function cidrToRangeIPv4($cidrParts)
	{
		$range = array();
		$startIP = ip2long($cidrParts[0]);
		$mask = -1 << (32 - (int) $cidrParts[1]);
		$range[0] = long2ip($startIP & $mask);
		$newStartIP = ip2long($range[0]);
		$range[1] = long2ip($newStartIP + pow(2, 32 - (int) $cidrParts[1]) - 1);
		return $range;
	}

	// adapted from https://stackoverflow.com/a/5858676
	public static function cidrToRange($cidr)
	{
		$cidrParts = explode('/', $cidr);
		if (self::isIPv6($cidrParts[0]))
		{
			return self::cidrToRangeIPv6($cidrParts);
		}
		return self::cidrToRangeIPv4($cidrParts);
	}
}
