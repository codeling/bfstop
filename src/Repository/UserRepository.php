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

	/**
	 * Whether $login is the username or the email address of an existing
	 * account (Joomla! can be set up to accept either at the login).
	 *
	 * Fail-open: no (so a username isn't taken for an account's, and no mail
	 * or notification which depends on that is sent).
	 */
	public function accountExists($login)
	{
		return $this->failOpen('accountExists', function () use ($login)
		{
			// LOWER: Joomla treats usernames case-insensitively on login
			// (MySQL's default collations do, PostgreSQL's don't)
			$query = $this->db->createQuery()
				->select('COUNT(*)')
				->from($this->db->quoteName('#__users'))
				->where('(LOWER('.$this->db->quoteName('username').') = LOWER(:login1)'.
					' OR LOWER('.$this->db->quoteName('email').') = LOWER(:login2))');
			$values = array('login1' => (string) $login, 'login2' => (string) $login);
			return $this->count($query, $values) > 0;
		}, false);
	}
}
