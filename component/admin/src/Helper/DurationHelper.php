<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Joomla\CMS\Language\Text;

class DurationHelper
{
	// the durations (in minutes) which have a string of their own
	private const Named = array(
		0 => 'COM_BFSTOP_BLOCK_UNLIMITED',
		5 => 'COM_BFSTOP_BLOCK_5MINUTES',
		10 => 'COM_BFSTOP_BLOCK_10MINUTES',
		15 => 'COM_BFSTOP_BLOCK_15MINUTES',
		30 => 'COM_BFSTOP_BLOCK_30MINUTES',
		60 => 'COM_BFSTOP_BLOCK_1HOUR',
		120 => 'COM_BFSTOP_BLOCK_2HOURS',
		240 => 'COM_BFSTOP_BLOCK_4HOURS',
		480 => 'COM_BFSTOP_BLOCK_8HOURS',
		1440 => 'COM_BFSTOP_BLOCK_24HOURS',
	);

	/**
	 * The duration of a block (in minutes, 0 = unlimited) as text. Blocks can
	 * last for any number of minutes, not only those of the block form: the
	 * plugin's settings offer a week and 30 days, and the progressive block
	 * duration multiplies the duration with each repeat offense.
	 */
	public static function toReadable($duration)
	{
		$duration = (int) $duration;
		if (array_key_exists($duration, self::Named))
		{
			return Text::_(self::Named[$duration]);
		}
		if ($duration % 1440 === 0)
		{
			return Text::plural('COM_BFSTOP_BLOCK_N_DAYS', intdiv($duration, 1440));
		}
		if ($duration % 60 === 0)
		{
			return Text::plural('COM_BFSTOP_BLOCK_N_HOURS', intdiv($duration, 60));
		}
		return Text::plural('COM_BFSTOP_BLOCK_N_MINUTES', $duration);
	}
}
