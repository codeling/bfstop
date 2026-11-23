<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Repository;

defined('_JEXEC') or die;

/**
 * What the plugin reads of Joomla's own accounts (#__users and the group
 * map), and nothing else of them.
 */
class UserRepository extends Repository
{
	/**
	 * The email address of the account with the id $id, null if there is
	 * none. Fail-open: null (no mail is sent).
	 */
	public function emailById($id)
	{
		return $this->failOpen('emailById', function () use ($id)
		{
			$query = $this->db->createQuery()
				->select($this->db->quoteName('email'))
				->from($this->db->quoteName('#__users'))
				->where($this->db->quoteName('id').' = :id');
			$values = array('id' => (int) $id);
			return $this->scalar($query, $values, 0, 1);
		}, null);
	}

	/**
	 * The enabled account whose username or email address is $login - what a
	 * failed login was typed with, see accountExists(), so matched the same
	 * way: whatever the case, and also by the email address. Null if there is
	 * no such account, or it is disabled (it can't log in, so an unblock link
	 * is of no use to it). If $login is the username of one account and the
	 * email address of another, the one whose username it is wins.
	 *
	 * Fail-open: null (so no mail is sent).
	 *
	 * @return array{username: string, email: string}|null
	 */
	public function accountByLogin($login)
	{
		$login = (string) $login;
		if ($login === '')
		{
			return null;
		}
		return $this->failOpen('accountByLogin', function () use ($login)
		{
			$values = array('u0' => $login, 'e0' => $login, 'o0' => $login);
			$query = $this->db->createQuery()
				->select($this->db->quoteName(array('username', 'email')))
				->from($this->db->quoteName('#__users'))
				->where('('.$this->loginCondition(array('u0'), array('e0')).')')
				->where($this->db->quoteName('block').' = 0')
				->order('CASE WHEN '.$this->loginCondition(array('o0'), array()).' THEN 0 ELSE 1 END')
				->order($this->db->quoteName('id'));
			$row = $this->row($query, $values, 0, 1);
			if (!is_array($row) || (string) $row['email'] === '')
			{
				return null;
			}
			return array('username' => (string) $row['username'], 'email' => (string) $row['email']);
		}, null);
	}

	/**
	 * The email addresses of the enabled members of the user group $groupId
	 * (not those of its sub-groups): a disabled account gets no mails.
	 * Fail-open: none.
	 *
	 * @return string[]
	 */
	public function emailsOfGroup($groupId)
	{
		return $this->failOpen('emailsOfGroup', function () use ($groupId)
		{
			$query = $this->db->createQuery()
				->select($this->db->quoteName('u.email'))
				->from($this->db->quoteName('#__users', 'u'))
				->innerJoin($this->db->quoteName('#__user_usergroup_map', 'g').
					' ON '.$this->db->quoteName('u.id').' = '.$this->db->quoteName('g.user_id'))
				->where($this->db->quoteName('g.group_id').' = :group')
				->where($this->db->quoteName('u.block').' = 0');
			$values = array('group' => (int) $groupId);
			return $this->column($query, $values);
		}, array());
	}

	/**
	 * The email addresses of the enabled accounts in the user groups
	 * $groupIds (the super users' groups) which receive system emails
	 * ("Receive System Emails" in their account) - or of all of them, if
	 * none does: a warning which concerns the whole site must reach
	 * somebody. Fail-open: none.
	 *
	 * @param int[] $groupIds
	 * @return string[]
	 */
	public function emailsOfGroupsForSystemMails(array $groupIds)
	{
		$groupIds = array_values(array_unique(array_filter(array_map('intval', $groupIds))));
		if (count($groupIds) === 0)
		{
			return array();
		}
		return $this->failOpen('emailsOfGroupsForSystemMails', function () use ($groupIds)
		{
			$query = $this->db->createQuery()
				->select($this->db->quoteName(array('u.email', 'u.sendEmail')))
				->from($this->db->quoteName('#__users', 'u'))
				->innerJoin($this->db->quoteName('#__user_usergroup_map', 'g').
					' ON '.$this->db->quoteName('u.id').' = '.$this->db->quoteName('g.user_id'))
				->whereIn($this->db->quoteName('g.group_id'), $groupIds)
				->where($this->db->quoteName('u.block').' = 0');
			$all = array();
			$system = array();
			foreach ($this->objects($query) as $row)
			{
				$all[] = (string) $row->email;
				if ((int) $row->sendEmail === 1)
				{
					$system[] = (string) $row->email;
				}
			}
			return array_values(array_unique(count($system) > 0 ? $system : $all));
		}, array());
	}

	// how many logins one query looks up (see anyAccountExists())
	private const LookupChunk = 500;

	/**
	 * Whether $login is the username or the email address of an existing
	 * account (Joomla! can be set up to accept either at the login).
	 *
	 * Fail-open: no (so a username isn't taken for an account's, and no mail
	 * or notification which depends on that is sent).
	 */
	public function accountExists($login)
	{
		return $this->anyAccountExists(array($login));
	}

	/**
	 * Whether any of $logins is the username or the email address of an
	 * existing account: one query for up to LookupChunk of them.
	 *
	 * Fail-open: no, as for accountExists().
	 *
	 * @param string[] $logins
	 */
	public function anyAccountExists(array $logins)
	{
		$logins = array_values(array_unique(array_map('strval', $logins)));
		if (count($logins) === 0)
		{
			return false;
		}
		return $this->failOpen('anyAccountExists', function () use ($logins)
		{
			foreach (array_chunk($logins, self::LookupChunk) as $chunk)
			{
				if ($this->accountAmong($chunk))
				{
					return true;
				}
			}
			return false;
		}, false);
	}

	/**
	 * Whether one of $logins (at most LookupChunk) is the username or email
	 * address of an account, by the indexes of both columns (see
	 * loginCondition()).
	 */
	private function accountAmong(array $logins): bool
	{
		$values = array();
		$usernames = array();
		$emails = array();
		foreach ($logins as $i => $login)
		{
			$values['u'.$i] = $login;
			$values['e'.$i] = $login;
			$usernames[] = 'u'.$i;
			$emails[] = 'e'.$i;
		}
		$query = $this->db->createQuery()
			->select('1')
			->from($this->db->quoteName('#__users'))
			->where('('.$this->loginCondition($usernames, $emails).')');
		return $this->scalar($query, $values, 0, 1) !== null;
	}

	/**
	 * SQL for "the username is one of the parameters $usernames, or the email
	 * address one of $emails" (names of parameters, without the colon), as
	 * Joomla looks an account up on login: case-insensitively. MySQL and
	 * MariaDB compare the columns that way themselves (their collation,
	 * utf8mb4_unicode_ci, is the one Joomla creates them with), and, unlike
	 * LOWER(), by index: with LOWER() every failed login read the whole table
	 * of accounts. PostgreSQL compares exactly, so there both sides are lowered
	 * (Joomla has no index on the lowered columns there).
	 */
	private function loginCondition(array $usernames, array $emails): string
	{
		$lower = $this->db->getServerType() === 'postgresql';
		$parts = array();
		foreach (array('username' => $usernames, 'email' => $emails) as $column => $parameters)
		{
			if (count($parameters) === 0)
			{
				continue;
			}
			$placeholders = array_map(function ($name) use ($lower)
			{
				return $lower ? 'LOWER(:'.$name.')' : ':'.$name;
			}, $parameters);
			$quoted = $this->db->quoteName($column);
			$parts[] = ($lower ? 'LOWER('.$quoted.')' : $quoted).' IN ('.implode(', ', $placeholders).')';
		}
		return implode(' OR ', $parts);
	}
}
