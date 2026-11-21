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
use Joomla\CMS\Language\Text;

class IpValidateHelper
{
	/**
	 * The shortest prefix length a network of the block and allow list may
	 * have: an allow list entry for a whole address family (0.0.0.0/0, ::/0)
	 * or a large share of it switches the protection off, a block of it
	 * shuts everybody out - which the check whether a block would include
	 * the current address misses if that is of the other family.
	 */
	public const MinPrefixIPv4 = 8;
	public const MinPrefixIPv6 = 16;

	/**
	 * Joomla shows the messages it is given as HTML, so what was typed into
	 * a form must not be put into one as it is.
	 */
	private static function e($text)
	{
		return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
	}

	/**
	 * What is wrong with $address as an entry of the block or allow list (an
	 * address, or a network in CIDR notation), as a message to show (escaped:
	 * it contains what was typed in); null if nothing is. The form rules
	 * return it as their error, which Joomla shows instead of its own.
	 */
	public static function rangeError($address): ?string
	{
		$address = (string) $address;
		$ip = $address;
		if (str_contains($address, '/'))
		{
			list($ip, $subnet) = explode('/', $address, 2);
			$maxBits = IpRangeHelper::isIPv6($ip) ? 128 : 32;
			// digits only: is_numeric() would also accept "1e1", "0x8" or " 8",
			// which don't mean what they look like in the places the range ends
			// up (e.g. the web server's configuration)
			if (preg_match('/^[0-9]{1,3}\z/', $subnet) !== 1 || (int) $subnet > $maxBits)
			{
				return Text::sprintf('COM_BFSTOP_IP_INVALID_SUBNET', self::e($subnet));
			}
			$minBits = IpRangeHelper::isIPv6($ip) ? self::MinPrefixIPv6 : self::MinPrefixIPv4;
			if ((int) $subnet < $minBits)
			{
				return Text::sprintf('COM_BFSTOP_IP_NETWORK_TOO_LARGE', self::e($address),
					self::MinPrefixIPv4, self::MinPrefixIPv6);
			}
		}
		if (!filter_var($ip, FILTER_VALIDATE_IP))
		{
			return Text::sprintf('COM_BFSTOP_IP_INVALID_ADDRESS', self::e($ip));
		}
		return null;
	}

	/**
	 * The note that $address (a valid entry, see rangeError()) is of a
	 * private or reserved range - which can be meant, so it is no error - or
	 * null if it isn't.
	 */
	public static function privateRangeNote($address): ?string
	{
		$ip = explode('/', (string) $address, 2)[0];
		return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)
			? null
			: Text::sprintf('COM_BFSTOP_IP_PRIVATE_OR_RESERVED', self::e($ip));
	}

	/**
	 * The error that $range (an address, or a network in CIDR notation)
	 * holds the address of the current client - a block of it would shut out
	 * whoever is entering it - or null if it doesn't. Matched by the
	 * library's IpHelper, like the block and allow list themselves.
	 */
	public static function currentIpError($range): ?string
	{
		$curIP = IpHelper::getAddress(LogHelper::getLogger());
		return IpHelper::contains($range, $curIP)
			? Text::sprintf('COM_BFSTOP_IP_BLOCKS_USER', self::e($range), self::e($curIP))
			: null;
	}
}
