<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Toolbar\ToolbarHelper as JoomlaToolbarHelper;

class ToolbarHelper
{
	public static function addOptions()
	{
		$user = Factory::getApplication()->getIdentity();
		if ($user && ($user->authorise('core.admin', 'com_bfstop') || $user->authorise('core.options', 'com_bfstop')))
		{
			JoomlaToolbarHelper::preferences('com_bfstop');
		}
	}
}
