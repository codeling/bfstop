<?php
/*
 * @package Brute Force Stop (bfstop) for Joomla! >=2.5
 * @author Bernhard Froehler
 * @copyright (C) 2012-2014 Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

class BFStopLogger {

	private $log_level;
	const LogCategory = 'bfstop';
	const Disabled = -1;

	function __construct($log_level)
	{
		$this->log_level = $log_level;
		$priorities = JLog::ALL;
		if ($log_level > self::Disabled)
		{
			JLog::addLogger(array(
				'text_file' => 'plg_system_bfstop.log.php',
				'text_entry_format' =>
					'{DATETIME} {PRIORITY} {MESSAGE}'
			),
			$priorities,
			array(self::LogCategory));
		}
	}

	function isEnabled($priority = JLog::ERROR) {
		return $priority <= $this->log_level;
	}

	function log($msg, $priority)
	{
		if ($this->isEnabled($priority)) {
			JLog::add($msg, $priority, self::LogCategory);
		}
	}
}
