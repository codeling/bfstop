<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Table;

defined('_JEXEC') or die;

use Joomla\CMS\Table\Table;
use Joomla\Database\DatabaseDriver;

class AllowTable extends Table
{
	function __construct(DatabaseDriver $db)
	{
		parent::__construct('#__bfstop_allowlist', 'id', $db);
	}

	public function check()
	{
		// a new entry comes with an empty id from the edit form; MySQL turns
		// that into the next auto-increment value, but PostgreSQL rejects it
		// (as NULL for the id column) - 0 makes Joomla leave the id out of
		// the INSERT on both (issue bfstop#206)
		if (empty($this->id))
		{
			$this->id = 0;
		}
		return parent::check();
	}
}
