<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;

class IpValidateHelper
{
	public static function validIPRange($address)
	{
		$ip = $address;
		$isSubNet = str_contains($address, "/");
		if ($isSubNet)
		{
			$parts = explode("/", $ip, 2);
			$subnet = $parts[1];
			$ip = $parts[0];
			$maxBits = IpRangeHelper::isIPv6($ip) ? 128 : 32;
			if (!is_numeric($subnet) || $subnet < 0 || $subnet > $maxBits)
			{
				Factory::getApplication()->enqueueMessage(Text::sprintf('COM_BFSTOP_IP_INVALID_SUBNET', $subnet), 'warning');
				return false;
			}
		}
		if (!filter_var($ip, FILTER_VALIDATE_IP))
		{
			Factory::getApplication()->enqueueMessage(Text::sprintf('COM_BFSTOP_IP_INVALID_ADDRESS', $ip), 'warning');
			return false;
		}
		if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE))
		{
			Factory::getApplication()->enqueueMessage(Text::sprintf('COM_BFSTOP_IP_PRIVATE_OR_RESERVED', $ip), 'warning');
		}
		return true;
	}

	private static function cidrMatchIPv6($ip, $subnet, $bits)
	{
		$ipBin = @inet_pton($ip);
		$subnetBin = @inet_pton($subnet);
		if ($ipBin === false || $subnetBin === false)
		{
			return false;
		}
		$mask = IpRangeHelper::ipv6Mask($bits);
		$subnetBin &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
		return ($ipBin & $mask) === $subnetBin;
	}

	// from https://stackoverflow.com/a/594134
	public static function cidrMatch($ip, $range)
	{
		$rangeParts = explode('/', $range);
		$subnet = $rangeParts[0];
		$isIPv6 = IpRangeHelper::isIPv6($subnet);
		$bits = isset($rangeParts[1]) ? (int) $rangeParts[1] : ($isIPv6 ? 128 : 32);

		if ($isIPv6)
		{
			return self::cidrMatchIPv6($ip, $subnet, $bits);
		}

		$ip = ip2long($ip);
		$subnet = ip2long($subnet);
		$mask = -1 << (32 - $bits);
		$subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
		return ($ip & $mask) == $subnet;
	}

	public static function matchesCurrentIP($range)
	{
		$curIP = IpHelper::getAddress(LogHelper::getLogger());
		$result = self::cidrMatch($curIP, $range);
		if ($result)
		{
			Factory::getApplication()->enqueueMessage(Text::sprintf('COM_BFSTOP_IP_BLOCKS_USER', $range, $curIP), 'warning');
		}
		return $result;
	}
}
