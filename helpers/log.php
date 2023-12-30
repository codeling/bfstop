<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Log\Log;

class BFStopLogger {

	private $log_level;
	const LogCategory = 'bfstop';
	const Disabled = -1;

	function __construct($log_level)
	{
		$this->log_level = $log_level;
		$priorities = Log::ALL;
		if ($log_level > self::Disabled)
		{
			Log::addLogger(array(
				'text_file' => 'plg_system_bfstop.log.php',
				'text_entry_format' =>
					'{DATETIME} {PRIORITY} {MESSAGE}'
			),
			$priorities,
			array(self::LogCategory));
		}
	}

	function isEnabled($priority = Log::ERROR) {
		return $priority <= $this->log_level;
	}

	function log($msg, $priority)
	{
		if ($this->isEnabled($priority)) {
			Log::add($msg, $priority, self::LogCategory);
		}
	}
}
