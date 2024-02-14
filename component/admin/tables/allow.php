<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Table\Table;

class BFStopTableAllow extends Table
{
	function __construct(&$db)
	{
		parent::__construct('#__bfstop_allowlist', 'id', $db);
	}
}
