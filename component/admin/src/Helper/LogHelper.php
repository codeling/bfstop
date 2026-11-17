<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Codeling\Library\Bfstop\Settings;

class LogHelper
{
	/**
	 * The log, at the level of the settings - also while the plugin is
	 * disabled: the page of an unblock link and the lists still work then.
	 */
	public static function getLogger()
	{
		return LoggerHelper::fromSettings(Settings::stored());
	}
}
