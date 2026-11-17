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
	 * The email address of the account with the username $username, null if
	 * there is none. Fail-open: null (no mail is sent).
	 */
	public function emailByUsername($username)
	{
		return $this->failOpen('emailByUsername', function () use ($username)
		{
			$query = $this->db->createQuery()
				->select($this->db->quoteName('email'))
				->from($this->db->quoteName('#__users'))
				->where($this->db->quoteName('username').' = :username');
			$values = array('username' => (string) $username);
			return $this->scalar($query, $values, 0, 1);
		}, null);
	}

	/**
	 * The email addresses of the members of the user group $groupId.
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
				->join('LEFT', $this->db->quoteName('#__user_usergroup_map', 'g').
					' ON '.$this->db->quoteName('u.id').' = '.$this->db->quoteName('g.user_id'))
				->where($this->db->quoteName('g.group_id').' = :group');
			$values = array('group' => (int) $groupId);
			return $this->column($query, $values);
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
	 * address of an account, by the indexes of both columns.
	 *
	 * Joomla looks an account up case-insensitively on login. MySQL and
	 * MariaDB compare the columns that way themselves (their collation,
	 * utf8mb4_unicode_ci, is the one Joomla creates them with), and, unlike
	 * LOWER(), by index: with LOWER() every failed login read the whole table
	 * of accounts. PostgreSQL compares exactly, so there both sides are lowered
	 * (Joomla has no index on the lowered columns there).
	 */
	private function accountAmong(array $logins): bool
	{
		$lower = $this->db->getServerType() === 'postgresql';
		$values = array();
		$usernames = array();
		$emails = array();
		foreach ($logins as $i => $login)
		{
			$values['u'.$i] = $login;
			$values['e'.$i] = $login;
			$usernames[] = $lower ? 'LOWER(:u'.$i.')' : ':u'.$i;
			$emails[] = $lower ? 'LOWER(:e'.$i.')' : ':e'.$i;
		}
		$username = $this->db->quoteName('username');
		$email = $this->db->quoteName('email');
		$condition = $lower
			? 'LOWER('.$username.') IN ('.implode(', ', $usernames).') OR LOWER('.$email.') IN ('.implode(', ', $emails).')'
			: $username.' IN ('.implode(', ', $usernames).') OR '.$email.' IN ('.implode(', ', $emails).')';
		$query = $this->db->createQuery()
			->select('1')
			->from($this->db->quoteName('#__users'))
			->where('('.$condition.')');
		return $this->scalar($query, $values, 0, 1) !== null;
	}
}
