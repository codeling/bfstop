<?php
defined('_JEXEC') or die;

class BFStopLogger {

	private $log_level;
	const LogCategory = 'bfstop';
	const Disabled = -1;

	function __construct($log_level)
	{
		$this->log_level = $log_level;
		if ($log_level > self::Disabled)
		{
			JLog::addLogger(array(
				'text_file' => 'plg_system_bfstop.log.php'
			), JLog::ALL,
			self::LogCategory);
		}
	}

	function isEnabled($priority = JLog::FATAL) {
		return $priority <= $this->log_level;
	}

	function log($msg, $priority)
	{
		if ($this->isEnabled($priority)) {
			JLog::add($msg, $priority, self::LogCategory);
		}
	}
}
