<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Repository;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Joomla\Database\DatabaseInterface;
use Joomla\Database\ParameterType;
use Joomla\Database\QueryInterface;

/**
 * The code which reads and writes one table (or two which belong together).
 *
 * The rules, so that none of them has to be checked in the code using one:
 * - the callers pass values (an address, a username, a time and a number of
 *   minutes), never SQL, and no table or column names;
 * - every value goes into a query as a bound parameter (the $values array
 *   given to execute(), scalar() and the like, or whereIn()), none is
 *   concatenated into it;
 * - a query is run by this class only (prepare() and the methods which
 *   fetch): no repository calls setQuery(), execute() or load*() of the
 *   database itself, so there is one place to count, log or time the
 *   queries of a request;
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
	 * Runs $work in a transaction: committed when it returns, rolled back when
	 * it throws. The exception goes on to the caller's failure policy (see
	 * failOpen()): this only makes sure the changes of $work are all or
	 * nothing.
	 */
	protected function inTransaction(callable $work)
	{
		$this->db->transactionStart();
		$committed = false;
		try
		{
			$result = $work();
			$this->db->transactionCommit();
			$committed = true;
			return $result;
		}
		finally
		{
			if (!$committed)
			{
				$this->db->transactionRollback();
			}
		}
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

	/**
	 * Makes $query - with $values (name => value) bound as its parameters -
	 * the database's query. Every query of a repository goes through here or
	 * through one of the methods which run it (execute(), scalar(), ...):
	 * what counts, logs or times the queries of a request hooks in here.
	 */
	protected function prepare(QueryInterface $query, array $values = array(), $offset = 0, $limit = 0)
	{
		self::bindValues($query, $values);
		$this->db->setQuery($query, $offset, $limit);
	}

	protected function execute(QueryInterface $query, array $values = array())
	{
		$this->prepare($query, $values);
		$this->db->execute();
	}

	protected function scalar(QueryInterface $query, array $values = array(), $offset = 0, $limit = 0)
	{
		$this->prepare($query, $values, $offset, $limit);
		return $this->db->loadResult();
	}

	protected function count(QueryInterface $query, array $values = array()): int
	{
		return (int) $this->scalar($query, $values);
	}

	protected function column(QueryInterface $query, array $values = array(), $offset = 0, $limit = 0)
	{
		$this->prepare($query, $values, $offset, $limit);
		return $this->db->loadColumn();
	}

	protected function row(QueryInterface $query, array $values = array(), $offset = 0, $limit = 0)
	{
		$this->prepare($query, $values, $offset, $limit);
		return $this->db->loadAssoc();
	}

	protected function objects(QueryInterface $query, array $values = array(), $offset = 0, $limit = 0)
	{
		$this->prepare($query, $values, $offset, $limit);
		return $this->db->loadObjectList();
	}

	/**
	 * Inserts the row $row (column => value; null values are left out, so
	 * the column gets its default) into $table, with every value bound.
	 * Instead of the database's insertObject(), which looks up the columns
	 * of the table first - a query per table and request on MySQL and
	 * MariaDB, two on PostgreSQL, so 1-2 more for each failed login - and
	 * quotes the values into the SQL.
	 *
	 * @param string|null $key the column of the generated id
	 * @return int|null the id of the new row, if $key is given
	 */
	protected function insert($table, array $row, $key = null)
	{
		$columns = array();
		$placeholders = array();
		$values = array();
		foreach ($row as $column => $value)
		{
			if ($value === null)
			{
				continue;
			}
			$name = 'c'.count($values);
			$columns[] = $this->db->quoteName($column);
			$placeholders[] = ':'.$name;
			$values[$name] = is_int($value) ? $value : (is_bool($value) ? (int) $value : (string) $value);
		}
		$query = $this->db->createQuery()
			->insert($this->db->quoteName($table))
			->columns($columns)
			->values(implode(',', $placeholders));
		if ($key === null)
		{
			$this->execute($query, $values);
			return null;
		}
		if ($this->db->getServerType() === 'postgresql')
		{
			$query->returning($this->db->quoteName($key));
			return (int) $this->scalar($query, $values);
		}
		$this->execute($query, $values);
		return (int) $this->db->insertid();
	}

	/** Deletes the rows of $table whose $column is before $date. */
	protected function deleteBefore($table, $column, $date)
	{
		$this->execute($this->db->createQuery()
			->delete($this->db->quoteName($table))
			->where($this->db->quoteName($column).' < :date'), array('date' => (string) $date));
	}

	/**
	 * The query counting the rows of $table whose $column is in the $minutes
	 * up to $time; $values gets its parameters. Whoever wants other columns
	 * clears the select.
	 */
	protected function windowQuery($table, $column, $time, $minutes, array &$values)
	{
		if ($minutes <= 0)
		{
			$this->logger->log("Invalid interval $minutes", \Joomla\CMS\Log\Log::WARNING);
		}
		$values = array('from' => self::minutesBefore($time, $minutes), 'to' => (string) $time);
		return $this->db->createQuery()
			->select('COUNT(*)')
			->from($this->db->quoteName($table))
			->where($this->db->quoteName($column).' BETWEEN :from AND :to');
	}

	/**
	 * SQL for "the user name is :$parameter, whatever the case", for the
	 * tables with a column username_lc (the user name in lower case, which the
	 * database computes): by index, where LOWER(username) = LOWER(:x) reads
	 * every row. The value is lowered by the database too, as it lowers the
	 * column.
	 */
	protected function usernameMatches($parameter): string
	{
		return $this->db->quoteName('username_lc').' = LOWER(:'.$parameter.')';
	}

	/**
	 * SQL of the column $column (a name of the calling repository's table)
	 * compared byte by byte: MySQL and MariaDB compare by the column's
	 * collation, which takes "muller", "müller" and "Müller" for the same
	 * (utf8mb4_unicode_ci) - for what has to tell those spellings apart.
	 * PostgreSQL compares exactly anyway.
	 */
	protected function exact($column): string
	{
		$quoted = $this->db->quoteName($column);
		return $this->db->getServerType() === 'mysql' ? 'CAST('.$quoted.' AS BINARY)' : $quoted;
	}

	protected static function daysAgo($days): string
	{
		return date('Y-m-d H:i:s', time() - $days * 86400);
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
			$excess = $this->count($this->db->createQuery()
				->select('COUNT(*)')
				->from($this->db->quoteName($table))) - (int) $maxRows;
			if ($excess <= 0)
			{
				return;
			}
			$keys = $this->column($this->db->createQuery()
				->select($this->db->quoteName($keyColumn))
				->from($this->db->quoteName($table))
				->order($orderBy), array(), 0, min($excess, $batch));
			if (count($keys) === 0)
			{
				return;
			}
			$this->execute($this->db->createQuery()
				->delete($this->db->quoteName($table))
				->whereIn($this->db->quoteName($keyColumn), $keys, $keyType));
		}
	}
}
