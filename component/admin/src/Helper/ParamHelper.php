<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Settings;

class ParamHelper
{
	/**
	 * A setting as it is stored now, or its default (see the library's
	 * Settings::get()). Costs no query: Joomla has the params of the
	 * components loaded.
	 *
	 * @param string $name the name of the setting
	 */
	public static function get($name)
	{
		return Settings::get(Settings::stored(), $name);
	}
}
