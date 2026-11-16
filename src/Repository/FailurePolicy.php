<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Repository;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use Joomla\CMS\Log\Log;

/**
 * What a repository does when the database fails.
 *
 * A lookup which can't be answered has to be taken for something. Which
 * answer is the safe one depends on what it is asked for, so every
 * repository operation names its policy where it is written (see
 * Repository::failOpen(), failClosed() and unknown()), and this is the one
 * place where a failure is handled:
 *
 * - FailOpen: the neutral answer which lets the visitor through and the
 *   plugin carry on - "no entries", 0 failed logins, "the failed login was
 *   not counted". Used where blocking somebody because the database hiccuped
 *   would do more harm than missing one attempt: counting, and the
 *   bookkeeping and maintenance, which are tried again.
 * - FailClosed: the answer which withholds what the lookup would have
 *   granted - "not on the allow list", "not a known address", "there is a
 *   current unblock token already", "other accounts were attacked". Used
 *   where the answer decides to trust an address or to send a link.
 * - Unknown: null, for whoever has to decide for itself what a list which
 *   can't be read means (the block list on a login attempt, see
 *   Bfstop::isBlocked()).
 *
 * Every failure is logged at error level in the same form, and counted:
 * failures() lets whoever shows a status see that the database misbehaved
 * during the request.
 */
final class FailurePolicy
{
	public const FailOpen = 'fail-open';
	public const FailClosed = 'fail-closed';
	public const Unknown = 'unknown';

	private static int $failures = 0;
	private static ?string $lastFailure = null;

	/**
	 * Runs $operation; if it throws, logs that, and returns $onFailure.
	 *
	 * @param string   $name      what failed, for the log: "Class::method"
	 * @param string   $mode      one of the constants of this class
	 * @param callable $operation
	 * @param mixed    $onFailure what the caller gets if the operation fails
	 */
	public static function guard(LoggerHelper $logger, $name, $mode, callable $operation, $onFailure)
	{
		try
		{
			return $operation();
		}
		catch (\Exception $e)
		{
			++self::$failures;
			self::$lastFailure = $name.': '.$e->getMessage();
			$logger->log('Database failure in '.$name.' ('.$mode.'): '.$e->getMessage(), Log::ERROR);
			return $onFailure;
		}
	}

	/**
	 * How many operations failed in this request.
	 */
	public static function failures(): int
	{
		return self::$failures;
	}

	public static function lastFailure(): ?string
	{
		return self::$lastFailure;
	}

	public static function reset(): void
	{
		self::$failures = 0;
		self::$lastFailure = null;
	}
}
