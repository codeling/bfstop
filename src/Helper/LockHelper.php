<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

/**
 * Exclusive locks on files, with a limit on how long they are waited for.
 *
 * flock() itself waits for as long as somebody else holds the lock - also
 * past PHP's time limit, which doesn't count the time spent waiting - so a
 * request which never lets go of a lock (it hangs, or somebody else on the
 * machine holds the file on purpose) would make every request after it hang
 * as well, each in a PHP worker of its own. Every wait here has an end.
 */
class LockHelper
{
	// how long a waiting request sleeps between two attempts, in microseconds
	private const PollInterval = 10000;

	/**
	 * Takes the exclusive lock on $file, creating the file if need be.
	 *
	 * @param string $file
	 * @param float  $timeout how many seconds to wait for it at most; 0 for
	 *                        one attempt
	 * @return resource|null|false the handle to give to release(); null if
	 *                             the lock was still held by somebody else
	 *                             when the time was up; false if the file
	 *                             can't be opened
	 */
	public static function acquire($file, $timeout)
	{
		$handle = @fopen($file, 'c');
		if ($handle === false)
		{
			return false;
		}
		$deadline = microtime(true) + max(0, (float) $timeout);
		while (!flock($handle, LOCK_EX | LOCK_NB))
		{
			if (microtime(true) >= $deadline)
			{
				fclose($handle);
				return null;
			}
			usleep(self::PollInterval);
		}
		return $handle;
	}

	/**
	 * Gives back a lock taken with acquire(). The operating system does the
	 * same when the request ends, however it ends.
	 */
	public static function release($handle)
	{
		if (is_resource($handle))
		{
			flock($handle, LOCK_UN);
			fclose($handle);
		}
	}
}
