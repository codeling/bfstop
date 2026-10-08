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
	// the log file moved out of the way when it gets too big; like the log
	// file it has to end in .php, as the web server must not hand out its contents
	public const RotatedLogFile = 'plg_system_bfstop.1.log.php';
	public const DefaultMaxSizeMB = 5;
	public const DefaultKeepDays = 28;
	// the log is rotated once it exceeds this size, so it can't fill up the
	// disk (a visitor can make the plugin log by failing logins)
	public const MaxLogFileBytes = self::DefaultMaxSizeMB * 1048576;

	private $maxBytes;

	public function __construct($log_level, $maxBytes = self::MaxLogFileBytes)
	{
		$this->log_level = $log_level;
		$this->maxBytes = $maxBytes;
		$priorities = Log::ALL;
		if ($log_level > self::Disabled)
		{
			self::rotateIfTooBig($maxBytes);
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
	 * The size limit of the log file in bytes, from the "log size limit"
	 * setting (given in MB); invalid values fall back to the default.
	 */
	public static function maxBytesFromMegabytes($megabytes)
	{
		$megabytes = (int) $megabytes;
		return ($megabytes > 0 ? $megabytes : self::DefaultMaxSizeMB) * 1048576;
	}

	private static function getLogPath()
	{
		$logPath = Factory::getApplication()->get('log_path');
		return $logPath ? rtrim($logPath, '/\\') : null;
	}

	/**
	 * Full paths of the log file and of its previous generation (whether
	 * they exist or not); empty if the log directory isn't known.
	 */
	public static function getLogFiles()
	{
		$logPath = self::getLogPath();
		return $logPath === null ? array() : array(
			$logPath.'/'.self::LogFile,
			$logPath.'/'.self::RotatedLogFile);
	}

	/**
	 * Moves the log file out of the way once it is too big, keeping one
	 * previous generation.
	 */
	public static function rotateIfTooBig($maxBytes = self::MaxLogFileBytes)
	{
		try
		{
			$logPath = self::getLogPath();
			if ($logPath === null)
			{
				return;
			}
			$file = $logPath.'/'.self::LogFile;
			clearstatcache(true, $file);
			if (is_file($file) && filesize($file) > $maxBytes)
			{
				@rename($file, $logPath.'/'.self::RotatedLogFile);
			}
		}
		catch (\Throwable $e)
		{
			// never let housekeeping of the log get in the way of the request
		}
	}

	/**
	 * Removes the log entries older than the given number of days from the log
	 * file and its previous generation, independent of the log level
	 * (there may be leftovers from the time logging was enabled).
	 * @return int the number of entries removed
	 */
	public static function pruneByAge($days)
	{
		$days = (int) $days;
		if ($days < 1)
		{
			return 0;
		}
		$removed = 0;
		foreach (self::getLogFiles() as $file)
		{
			try
			{
				$removed += self::pruneFile($file, time() - $days * 86400);
			}
			catch (\Throwable $e)
			{
				// see rotateIfTooBig()
			}
		}
		return $removed;
	}

	/**
	 * Rewrites the file in place, without the entries from before $cutoff.
	 * Every entry starts with a timestamp; lines that don't (e.g. the file
	 * header, or a message containing line breaks) are kept or dropped
	 * together with the entry before them. Entries other requests add while
	 * the file is rewritten may get lost, which is acceptable for a log.
	 */
	private static function pruneFile($file, $cutoff)
	{
		clearstatcache(true, $file);
		if (!is_file($file) || !($handle = @fopen($file, 'c+')))
		{
			return 0;
		}
		$removed = 0;
		try
		{
			if (!flock($handle, LOCK_EX | LOCK_NB))
			{
				return 0; // somebody else is pruning right now
			}
			$kept = tmpfile();
			$keep = true;
			while (($line = fgets($handle)) !== false)
			{
				if (preg_match('/^\d{4}-\d\d-\d\dT\S+/', $line, $match))
				{
					$time = strtotime($match[0]);
					$keep = ($time === false || $time >= $cutoff);
					$removed += $keep ? 0 : 1;
				}
				if ($keep)
				{
					fwrite($kept, $line);
				}
			}
			if ($removed > 0)
			{
				rewind($kept);
				rewind($handle);
				ftruncate($handle, 0);
				stream_copy_to_stream($kept, $handle);
				fflush($handle);
			}
			fclose($kept);
			flock($handle, LOCK_UN);
		}
		finally
		{
			fclose($handle);
		}
		return $removed;
	}

	/**
	 * Deletes the log file and its previous generation.
	 * @return int the number of files deleted
	 */
	public static function deleteLogFiles()
	{
		$deleted = 0;
		foreach (self::getLogFiles() as $file)
		{
			if (is_file($file) && @unlink($file))
			{
				++$deleted;
			}
		}
		return $deleted;
	}

	/**
	 * $text with control characters (line breaks above all) replaced by spaces:
	 * values a visitor chooses - like the username of a failed login - must not
	 * be able to forge further lines in the log or in a mail.
	 */
	public static function singleLine($text)
	{
		return preg_replace('/[\x00-\x1f\x7f]+/', ' ', (string) $text);
	}

	public function isEnabled($priority = Log::ERROR)
	{
		return $priority <= $this->log_level;
	}

	public function log($msg, $priority)
	{
		if ($this->isEnabled($priority))
		{
			Log::add(self::singleLine($msg), $priority, self::LogCategory);
		}
	}
}
