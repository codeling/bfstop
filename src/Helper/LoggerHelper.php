<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;

class LoggerHelper
{
	private $log_level;
	public const LogCategory = 'bfstop';
	public const Disabled = -1;
	public const LogFile = 'plg_system_bfstop.log.php';
	// the log is rotated once it exceeds this size, so it can't fill up the
	// disk (a visitor can make the plugin log by failing logins)
	public const MaxLogFileBytes = 5242880;

	public function __construct($log_level)
	{
		$this->log_level = $log_level;
		$priorities = Log::ALL;
		if ($log_level > self::Disabled)
		{
			self::rotateIfTooBig();
			Log::addLogger(array(
				'text_file' => self::LogFile,
				'text_entry_format' =>
					'{DATETIME} {PRIORITY} {MESSAGE}'
			),
			$priorities,
			array(self::LogCategory));
		}
	}

	/**
	 * Moves the log file out of the way once it is too big, keeping one
	 * previous generation. The old file keeps a .php extension (the file
	 * names end in .log.php) as the web server must not hand out its contents.
	 */
	public static function rotateIfTooBig($maxBytes = self::MaxLogFileBytes)
	{
		try
		{
			$logPath = Factory::getApplication()->get('log_path');
			$file = $logPath.'/'.self::LogFile;
			clearstatcache(true, $file);
			if ($logPath && is_file($file) && filesize($file) > $maxBytes)
			{
				@rename($file, $logPath.'/'.str_replace('.log.php', '.1.log.php', self::LogFile));
			}
		}
		catch (\Throwable $e)
		{
			// never let housekeeping of the log get in the way of the request
		}
	}

	public function isEnabled($priority = Log::ERROR)
	{
		return $priority <= $this->log_level;
	}

	public function log($msg, $priority)
	{
		if ($this->isEnabled($priority))
		{
			Log::add($msg, $priority, self::LogCategory);
		}
	}
}
