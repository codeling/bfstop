<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Joomla\Database\DatabaseInterface;

class OrderingHelper
{
	/**
	 * The ORDER BY clause of a list: the column if it is one of $allowed
	 * (the model's filter fields), else $defaultColumn, as an identifier,
	 * and ASC or DESC. The column and direction come from the request:
	 * Joomla's ListModel::populateState() checks them against the filter
	 * fields too, but escape() - meant for string literals - would not keep
	 * anything else out of the query if that check ever let it through.
	 */
	public static function clause(DatabaseInterface $db, $column, $direction, array $allowed, $defaultColumn, $defaultDirection)
	{
		$column = in_array((string) $column, $allowed, true) ? (string) $column : $defaultColumn;
		$direction = strtoupper((string) $direction);
		if ($direction !== 'ASC' && $direction !== 'DESC')
		{
			$direction = $defaultDirection;
		}
		return $db->quoteName($column).' '.$direction;
	}
}
