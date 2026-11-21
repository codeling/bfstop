<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

class LinkHelper
{
	public static function getIpInfoLink($ipaddress)
	{
		// a page of the backend, which has no menu items
		return 'index.php?option=com_bfstop&view=ipinfo&ipaddress='.rawurlencode((string) $ipaddress);
	}
}
