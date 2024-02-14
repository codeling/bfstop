<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

function numOfAddresses($cidr) {
    $cidr = explode('/', $cidr);
    return pow(2, (32 - (int)$cidr[1]));
}

// adapted from https://stackoverflow.com/a/5858676
function cidrToRange($cidr) {
    $range = array();
    $cidrParts = explode('/', $cidr);
    $startIP = ip2long($cidrParts[0]);
    $mask = -1 << (32 - (int)$cidrParts[1]);
    $range[0] = long2ip($startIP & $mask);
    $newStartIP = ip2long($range[0]);
    $range[1] = long2ip($newStartIP + numOfAddresses($cidr) - 1);
    return $range;
}
