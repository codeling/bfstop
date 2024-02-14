<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;

$pluginHelperDir = JPATH_SITE.'/plugins/system/bfstop/helpers/';
require_once($pluginHelperDir.'ipaddress.php');

function validIPRange($address)
{
	$ip = $address;
	$isSubNet = str_contains($address, "/");
	if ($isSubNet)
	{
		$parts = explode("/", $ip, 2);
		$subnet = $parts[1];
		if (!is_numeric($subnet) || $subnet < 0 || $subnet > 31)
		{
			Factory::getApplication()->enqueueMessage(Text::sprintf('COM_BFSTOP_IP_INVALID_SUBNET', $subnet), 'warning');
			return false;
		}
		$ip = $parts[0];
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

// from https://stackoverflow.com/a/594134
function cidr_match($ip, $range)
{
	list ($subnet, $bits) = explode('/', $range);
	if ($bits === null) {
		$bits = 32;
	}
	$ip = ip2long($ip);
	$subnet = ip2long($subnet);
	$mask = -1 << (32 - $bits);
	$subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
	return ($ip & $mask) == $subnet;
}

function matchesCurrentIP($range)
{
	$curIP = getIPAddr(getLogger());
	$result = cidr_match($curIP, $range);
	if ($result)
	{
		Factory::getApplication()->enqueueMessage(Text::sprintf('COM_BFSTOP_IP_BLOCKS_USER', $range, $curIP), 'warning');
	}
	return $result;
}

