<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Repository;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
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
			$entries = $this->loadMatching($ipaddress, function ($query) use (&$now)
			{
				$query->where($this->activeCondition('t', 'u'));
				$values = array('now' => $now);
				self::bindValues($query, $values);
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
			self::bindValues($query, $values);
			$this->db->setQuery($query);
			return $this->db->loadColumn();
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
			$this->db->setQuery($this->db->createQuery()
				->select('DISTINCT '.$this->db->quoteName('ipaddress'))
				->from($this->db->quoteName(self::Table)));
			return $this->db->loadColumn();
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
			self::bindValues($query, $values);
			$this->db->setQuery($query);
			$this->db->execute();
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
			$entry = new \stdClass();
			$entry->ipaddress = IpHelper::canonicalEntry($ipaddress) ?? $ipaddress;
			$entry->crdate = self::now();
			$entry->duration = $duration;
			if (!$this->db->insertObject(self::Table, $entry, 'id'))
			{
				$this->logger->log('Insert block entry failed!', \Joomla\CMS\Log\Log::ERROR);
				return -1;
			}
			return $entry->id;
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
			$time = self::now();
			$query = $this->db->createQuery()
				->select('COUNT(*)')
				->from($this->db->quoteName(self::Table, 't'))
				->where($this->db->quoteName('t.crdate').' BETWEEN :from AND :to')
				->where($this->db->quoteName('t.ipaddress').' = :ip')
				->where('NOT EXISTS (SELECT 1 FROM #__bfstop_unblock u WHERE t.id = u.block_id AND source = 0)');
			$values = array('from' => self::minutesBefore($time, self::UnlimitedDuration),
				'to' => $time, 'ip' => (string) $ipaddress);
			self::bindValues($query, $values);
			$this->db->setQuery($query);
			return (int) $this->db->loadResult();
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
			$query = $this->db->createQuery()
				->select('COUNT(*)')
				->from($this->db->quoteName(self::Table))
				->where($this->db->quoteName('crdate').' BETWEEN :from AND :to');
			$values = array('from' => self::minutesBefore($time, $minutes), 'to' => (string) $time);
			self::bindValues($query, $values);
			$this->db->setQuery($query);
			return (int) $this->db->loadResult();
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
			self::bindValues($query, $values);
			$this->db->setQuery($query);
			$this->db->execute();

			$this->db->setQuery('DELETE FROM #__bfstop_unblock WHERE NOT EXISTS '.
				'(SELECT 1 FROM #__bfstop_bannedip b WHERE b.id = #__bfstop_unblock.block_id)');
			$this->db->execute();
		}, null);
	}
}
