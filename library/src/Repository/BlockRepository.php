<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Repository;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\IpHelper;
use Joomla\CMS\Log\Log;
use Joomla\Database\ParameterType;

/**
 * The blocks (#__bfstop_bannedip) and their lifting (#__bfstop_unblock).
 * A block is active while its duration (in minutes, 0 for ever) hasn't run
 * out and it hasn't been lifted.
 */
class BlockRepository extends AddressTableRepository
{
	protected const Table = '#__bfstop_bannedip';
	protected const MatchLabel = 'Blocked';

	// 10 years in minutes. For all intents here sufficiently large to stand for "forever":
	public const UnlimitedDuration = 5256000;

	// who lifted a block (the source of its #__bfstop_unblock row): an
	// administrator in the block list, or the user through the link of a mail
	public const LiftedByAdministrator = 0;
	public const LiftedByToken = 1;

	private const LiftTable = '#__bfstop_unblock';

	// SQL for "the block t is active at :now"; names of columns and tables only
	private function activeCondition($block, $lifted)
	{
		return '('.$block.'.duration = 0 OR '.
			$this->addMinutesSql($block.'.crdate', $block.'.duration').' >= :now)'.
			' AND NOT EXISTS (SELECT 1 FROM #__bfstop_unblock '.$lifted.' WHERE '.$block.'.id = '.$lifted.'.block_id)';
	}

	/**
	 * The ids of the active blocks which contain $ipaddress, whether as the
	 * address itself or as part of a blocked network.
	 *
	 * Unknown (null) if the block list can't be read: whoever must not take
	 * that for "not blocked" (a login attempt) asks for this; whoever may
	 * (a page view: a database which is down doesn't serve the page anyway)
	 * takes it for no blocks.
	 *
	 * @return int[]|null
	 */
	public function activeIdsFor($ipaddress)
	{
		return $this->unknown('activeIdsFor', function () use ($ipaddress)
		{
			$now = self::now();
			$entries = $this->loadMatching($ipaddress, function ($query) use ($now)
			{
				$query->where($this->activeCondition('t', 'u'));
				return array('now' => $now);
			});
			return array_map(function ($entry)
			{
				return (int) $entry->id;
			}, $entries);
		});
	}

	/**
	 * Whether $ipaddress is blocked now. Whoever must not take a block list
	 * which can't be read for "not blocked" asks activeIdsFor().
	 */
	public function isBlocked($ipaddress)
	{
		return count($this->activeIdsFor($ipaddress) ?? array()) > 0;
	}

	/**
	 * The addresses which have been blocked, but are not any more: the block
	 * has run out or was lifted, and no other block of the same address is
	 * active. For blocking through the web server's configuration, which
	 * knows nothing about durations.
	 *
	 * Fail-open: none (nothing is taken out of the web server's file).
	 *
	 * @return string[]
	 */
	public function addressesWithoutActiveBlock()
	{
		return $this->failOpen('addressesWithoutActiveBlock', function ()
		{
			$query = $this->db->createQuery()
				->select('DISTINCT b.ipaddress')
				->from($this->db->quoteName(self::Table, 'b'))
				->where('NOT EXISTS (SELECT 1 FROM #__bfstop_bannedip c WHERE c.ipaddress = b.ipaddress AND '.
					$this->activeCondition('c', 'cu').')');
			$values = array('now' => self::now());
			return $this->column($query, $values);
		}, array());
	}

	/**
	 * Every address and network of the block list, whether its block is
	 * active or not.
	 *
	 * @return string[]|null null (unknown) if the block list could not be read
	 */
	public function allAddresses()
	{
		return $this->unknown('allAddresses', function ()
		{
			return $this->column($this->db->createQuery()
				->select('DISTINCT '.$this->db->quoteName('ipaddress'))
				->from($this->db->quoteName(self::Table)));
		});
	}

	/**
	 * Count a rejected request against the given blocks and remember when it
	 * happened (issue #219), so that stale blocks can be identified.
	 *
	 * Fail-open: the request is not counted.
	 *
	 * @param int[] $blockIds
	 */
	public function recordAttempt(array $blockIds)
	{
		if (count($blockIds) === 0)
		{
			return;
		}
		$this->failOpen('recordAttempt', function () use ($blockIds)
		{
			$query = $this->db->createQuery()
				->update($this->db->quoteName(self::Table))
				->set($this->db->quoteName('attempts').' = '.$this->db->quoteName('attempts').' + 1')
				->set($this->db->quoteName('last_attempt').' = :now')
				->whereIn($this->db->quoteName('id'), array_map('intval', $blockIds));
			$values = array('now' => self::now());
			$this->execute($query, $values);
		}, null);
	}

	/**
	 * Adds a block.
	 *
	 * @return int the id of the block, -1 if it could not be added (fail-open:
	 *             the caller carries on without a block, and says so)
	 */
	public function add($ipaddress, $duration)
	{
		return $this->failOpen('add', function () use ($ipaddress, $duration)
		{
			// a failed insert throws: fail-open, see above
			return $this->insert(self::Table, array('ipaddress' => IpHelper::canonicalEntry($ipaddress) ?? $ipaddress,
				'crdate' => self::now(), 'duration' => (int) $duration), 'id');
		}, -1);
	}

	/**
	 * How many blocks of $ipaddress there have been, the lifted ones (by an
	 * administrator, not by the user through the link of a mail) not counted:
	 * what the next block's duration is based on.
	 *
	 * Fail-open: 0 (no earlier blocks, so the shortest duration).
	 */
	public function countPrevious($ipaddress)
	{
		return $this->failOpen('countPrevious', function () use ($ipaddress)
		{
			$values = array();
			$query = $this->windowQuery(self::Table, 'crdate', self::now(), self::UnlimitedDuration, $values)
				->where($this->db->quoteName('ipaddress').' = :ip')
				->where('NOT EXISTS (SELECT 1 FROM #__bfstop_unblock u WHERE '.self::Table.'.id = u.block_id AND source = '.self::LiftedByAdministrator.')');
			$values['ip'] = (string) $ipaddress;
			return $this->count($query, $values);
		}, 0);
	}

	/**
	 * How many blocks were made in the $minutes up to $time (to limit the
	 * number of notifications).
	 *
	 * Fail-open: 0.
	 */
	public function countCreatedInWindow($time, $minutes)
	{
		return $this->failOpen('countCreatedInWindow', function () use ($time, $minutes)
		{
			$values = array();
			return $this->count($this->windowQuery(self::Table, 'crdate', $time, $minutes, $values), $values);
		}, 0);
	}

	/**
	 * Deletes the blocks which ended before $date, and the records of lifting
	 * which belong to no block (any more). Fail-open: the next run does it.
	 */
	public function purgeEndedBefore($date)
	{
		$this->failOpen('purgeEndedBefore', function () use ($date)
		{
			$query = $this->db->createQuery()
				->delete($this->db->quoteName(self::Table))
				->where($this->db->quoteName('duration').' != 0')
				->where($this->addMinutesSql('crdate', 'duration').' < :date');
			$values = array('date' => (string) $date);
			$this->execute($query, $values);

			$this->execute($this->db->createQuery()
				->delete('#__bfstop_unblock')
				->where('NOT EXISTS (SELECT 1 FROM #__bfstop_bannedip b WHERE b.id = #__bfstop_unblock.block_id)'));
		}, null);
	}

	/**
	 * Lifts the blocks $ids: whoever is blocked by them gets through again
	 * (the blocks themselves stay, the next block's duration is based on
	 * them, see countPrevious()). Only blocks which exist are lifted: block
	 * ids are handed out in order, so a record for one which doesn't exist
	 * yet would lift a block to come in advance - whoever may unblock could
	 * switch the blocking off that way, which takes the permission to change
	 * the settings. A block which was lifted already is left as it is; the
	 * others given with it are still lifted.
	 *
	 * Fail-closed, block by block: one which can't be lifted stays.
	 *
	 * @param int[] $ids
	 * @param int   $source LiftedByAdministrator or LiftedByToken
	 * @return bool whether all the blocks of $ids which exist are lifted now;
	 *              false if none is given
	 */
	public function lift(array $ids, $source): bool
	{
		if (count($ids) === 0)
		{
			$this->logger->log('No blocks given to lift!', Log::ERROR);
			return false;
		}
		$result = true;
		$now = self::now();
		foreach ($ids as $id)
		{
			$id = (int) $id;
			$outcome = $this->failClosed('lift', function () use ($id, $source, $now)
			{
				$values = array('id' => $id);
				if ($this->count($this->db->createQuery()
					->select('COUNT(*)')
					->from($this->db->quoteName(self::Table))
					->where($this->db->quoteName('id').' = :id'), $values) === 0)
				{
					return "There is no block $id";
				}
				if ($this->count($this->db->createQuery()
					->select('COUNT(*)')
					->from($this->db->quoteName(self::LiftTable))
					->where($this->db->quoteName('block_id').' = :id'), $values) > 0)
				{
					return "Block $id was lifted already";
				}
				// a failed insert throws: fail-closed, see above
				$this->insert(self::LiftTable, array('block_id' => $id, 'source' => (int) $source, 'crdate' => $now));
				return true;
			}, false);
			if ($outcome === true)
			{
				$this->logger->log("Lifted block $id", Log::INFO);
			}
			elseif ($outcome === false)
			{
				$result = false;
				$this->logger->log("Could not lift block $id!", Log::ERROR);
			}
			else
			{
				$this->logger->log($outcome, Log::INFO);
			}
		}
		return $result;
	}
}
