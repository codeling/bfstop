<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;

class BFStopLinkHelper
{
	public static function getIpInfoLink($ipaddress)
	{
		$input = Factory::getApplication()->input;
		$menuId = $input->get('Itemid', 0, 'INTEGER');
		$link = 'index.php?option=com_bfstop&Itemid='.$menuId.'&view=ipinfo&ipaddress='.$ipaddress;
		return $link;
	}
}
