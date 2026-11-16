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
use Joomla\Database\DatabaseInterface;
use Joomla\Database\ParameterType;
use Joomla\Database\QueryInterface;

/**
 * The code which reads and writes one table (or two which belong together).
 *
 * The rules, so that none of them has to be checked in the code using one:
 * - the callers pass values (an address, a username, a time and a number of
 *   minutes), never SQL, and no table or column names;
 * - every value goes into a query as a bound parameter (bind(), whereIn()),
 *   none is concatenated into it;
 * - what happens if the database fails is decided in the method, with
 *   failOpen(), failClosed() or unknown() - see FailurePolicy.
 */
abstract class Repository
{
	protected DatabaseInterface $db;
	protected LoggerHelper $logger;

	public function __construct(DatabaseInterface $db, LoggerHelper $logger)
	{
		$this->db = $db;
		$this->logger = $logger;
	}

	protected function failOpen($name, callable $operation, $neutral)
	{
		return FailurePolicy::guard($this->logger, static::class.'::'.$name, FailurePolicy::FailOpen, $operation, $neutral);
	}

	protected function failClosed($name, callable $operation, $safe)
	{
		return FailurePolicy::guard($this->logger, static::class.'::'.$name, FailurePolicy::FailClosed, $operation, $safe);
	}

	protected function unknown($name, callable $operation)
	{
		return FailurePolicy::guard($this->logger, static::class.'::'.$name, FailurePolicy::Unknown, $operation, null);
	}

	/**
	 * Binds every value of $values as the parameter of its key (":key").
	 * The values are bound by reference, so $values must be a variable which
	 * is still there when the query is executed: it is, as the query is
	 * run in the method which built it.
	 */
	protected static function bindValues(QueryInterface $query, array &$values)
	{
		foreach ($values as $name => &$value)
		{
			$query->bind(':'.$name, $value, is_int($value) ? ParameterType::INTEGER : ParameterType::STRING);
		}
		unset($value);
		return $query;
	}

	protected static function now(): string
	{
		return date('Y-m-d H:i:s');
	}

	/**
	 * $time (as written by date("Y-m-d H:i:s")) moved back by $minutes;
	 * computed in PHP so that no database-specific date arithmetic (like
	 * MySQL's DATE_SUB) is needed, see issue #206
	 */
	protected static function minutesBefore($time, $minutes): string
	{
		return date('Y-m-d H:i:s', strtotime($time) - ((int) $minutes) * 60);
	}

	/**
	 * SQL expression for $dateColumn + $minutesColumn minutes, for the cases
	 * where the number of minutes comes from a column and can therefore not
	 * be computed in PHP. Neither DATE_ADD nor Joomla's
	 * DatabaseQuery::dateAdd() work on PostgreSQL for this (issue #206). Both
	 * arguments are names of columns of the calling repository's table, never
	 * values.
	 */
	protected function addMinutesSql($dateColumn, $minutesColumn): string
	{
		if ($this->db->getServerType() === 'postgresql')
		{
			return '('.$dateColumn.' + '.$minutesColumn." * INTERVAL '1 minute')";
		}
		return 'DATE_ADD('.$dateColumn.', INTERVAL '.$minutesColumn.' MINUTE)';
	}

	/**
	 * Deletes the rows of $table which are over $maxRows, those which sort
	 * first by $orderBy first, in rounds of at most $batch rows (each round
	 * one query for the number of rows, one for the keys, one delete; at
	 * most 1000 rounds, so a maintenance run ends).
	 *
	 * $table, $keyColumn and $orderBy are the repository's own constants.
	 *
	 * @param string $keyType a ParameterType
	 */
	protected function trimOldest($table, $keyColumn, $orderBy, $maxRows, $batch, $keyType)
	{
		for ($round = 0; $round < 1000; ++$round)
		{
			$this->db->setQuery($this->db->createQuery()
				->select('COUNT(*)')
				->from($this->db->quoteName($table)));
			$excess = ((int) $this->db->loadResult()) - (int) $maxRows;
			if ($excess <= 0)
			{
				return;
			}
			$this->db->setQuery($this->db->createQuery()
				->select($this->db->quoteName($keyColumn))
				->from($this->db->quoteName($table))
				->order($orderBy), 0, min($excess, $batch));
			$keys = $this->db->loadColumn();
			if (count($keys) === 0)
			{
				return;
			}
			$this->db->setQuery($this->db->createQuery()
				->delete($this->db->quoteName($table))
				->whereIn($this->db->quoteName($keyColumn), $keys, $keyType));
			$this->db->execute();
		}
	}
}
