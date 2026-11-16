<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Repository;

defined('_JEXEC') or die;

/**
 * The tokens in the links of unblock mails (#__bfstop_unblock_token).
 */
class UnblockTokenRepository extends Repository
{
	private const Table = '#__bfstop_unblock_token';

	// how long an emailed unblock token can be used
	public const ValidDays = 3;

	/**
	 * What is stored of an unblock token. The token itself is a secret which
	 * only the mail holds: whoever reads the table (a backup, an SQL injection
	 * somewhere else on the site) must not get working links out of it. The
	 * token has 160 random bits, so a plain hash is enough; it is cut to the
	 * 40 characters of the column.
	 */
	public static function hash($token)
	{
		return substr(hash('sha256', (string) $token), 0, 40);
	}

	private static function validSince(): string
	{
		return date('Y-m-d H:i:s', time() - self::ValidDays * 86400);
	}

	/**
	 * Stores the token for the block $blockId.
	 *
	 * Fail-open: null, the caller doesn't send a link which wouldn't work.
	 *
	 * @param string      $token    the token to put into the link; only its hash is stored
	 * @param string|null $username the user the link is sent to, if any
	 * @return string|null $token, or null if it could not be stored
	 */
	public function add($blockId, $token, $username = null)
	{
		return $this->failOpen('add', function () use ($blockId, $token, $username)
		{
			$entry = new \stdClass();
			$entry->token = self::hash($token);
			$entry->block_id = $blockId;
			$entry->crdate = self::now();
			$entry->username = $username;
			if (!$this->db->insertObject(self::Table, $entry))
			{
				$this->logger->log('Insert unblock token failed!', \Joomla\CMS\Log\Log::ERROR);
				return null;
			}
			return $token;
		}, null);
	}

	/**
	 * Whether $token is an unexpired unblock token issued for one of the
	 * given blocks. Used to decide if a blocked client may reach the unblock
	 * page: a token that belongs to a different IP address's block, or one
	 * that has outlived its validity, must not work as a pass for this one.
	 *
	 * Fail-closed: not valid.
	 */
	public function validForBlocks($token, array $blockIds)
	{
		if ($token === '' || count($blockIds) === 0)
		{
			return false;
		}
		return $this->failClosed('validForBlocks', function () use ($token, $blockIds)
		{
			$query = $this->db->createQuery()
				->select($this->db->quoteName(array('block_id', 'crdate')))
				->from($this->db->quoteName(self::Table))
				->where($this->db->quoteName('token').' = :token');
			$values = array('token' => self::hash($token));
			self::bindValues($query, $values);
			$this->db->setQuery($query);
			$row = $this->db->loadAssoc();
			if ($row === null || !in_array((int) $row['block_id'], $blockIds, true))
			{
				return false;
			}
			$created = strtotime($row['crdate']);
			return $created !== false && (time() - $created) <= (self::ValidDays * 86400);
		}, false);
	}

	/**
	 * Whether an unblock link which can still be used was sent to $username:
	 * one that hasn't expired and wasn't used (a used token is deleted).
	 *
	 * Fail-closed: yes - no second link goes out, which is the safe side of
	 * "is somebody asking for links in a loop".
	 */
	public function hasCurrentFor($username)
	{
		return $this->failClosed('hasCurrentFor', function () use ($username)
		{
			$query = $this->db->createQuery()
				->select('COUNT(*)')
				->from($this->db->quoteName(self::Table))
				->where('LOWER('.$this->db->quoteName('username').') = LOWER(:username)')
				->where($this->db->quoteName('crdate').' >= :since');
			$values = array('username' => (string) $username, 'since' => self::validSince());
			self::bindValues($query, $values);
			$this->db->setQuery($query);
			return ((int) $this->db->loadResult()) > 0;
		}, true);
	}

	/**
	 * Whether the token (any, expired or not) is stored.
	 *
	 * Fail-closed: no.
	 */
	public function exists($token)
	{
		return $this->failClosed('exists', function () use ($token)
		{
			$query = $this->db->createQuery()
				->select($this->db->quoteName('token'))
				->from($this->db->quoteName(self::Table))
				->where($this->db->quoteName('token').' = :token');
			$values = array('token' => self::hash($token));
			self::bindValues($query, $values);
			$this->db->setQuery($query);
			return $this->db->loadResult() != null;
		}, false);
	}

	/**
	 * Deletes the tokens which can't be used any more. A used token is
	 * deleted when it is used, and the unblock page deletes the expired ones
	 * when somebody visits it - but nobody may, and the purge by age only runs
	 * if a purge age is configured. Fail-open: the next run does it.
	 */
	public function purgeExpired()
	{
		$this->purgeBefore(self::validSince());
	}

	/**
	 * Deletes the tokens made before $date. Fail-open: the next run does it.
	 */
	public function purgeBefore($date)
	{
		$this->failOpen('purgeBefore', function () use ($date)
		{
			$query = $this->db->createQuery()
				->delete($this->db->quoteName(self::Table))
				->where($this->db->quoteName('crdate').' < :date');
			$values = array('date' => (string) $date);
			self::bindValues($query, $values);
			$this->db->setQuery($query);
			$this->db->execute();
		}, null);
	}
}
