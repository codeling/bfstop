<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Helper\NotifierHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;

/**
 * A NotifierHelper which records the mails instead of handing them to the
 * mailer: what the notifier decides (whether to mail, whom, what it says) is
 * the subject of the tests, not Joomla's transport.
 */
class RecordingNotifier extends NotifierHelper
{
	/** array('subject' => ..., 'body' => ..., 'to' => string[]) per mail */
	public $mails = array();

	public function sendMail($subject, $body, $emailAddresses)
	{
		$this->mails[] = array('subject' => $subject, 'body' => $body, 'to' => $emailAddresses);
		return true;
	}
}

/**
 * Which mails the notifier sends: to whom, how many (the limit of
 * notifications per day), and what they say. The notifications of the admin
 * and the unblock mail of the blocked user are the ones which tell an
 * administrator that somebody is attacking the site - and a user how to get
 * back in - so they must not silently stop coming, or come without limit.
 */
class NotifierMailTest extends IntegrationTestCase
{
	private const Ip = '203.0.113.5';

	private $createdUsers = array();

	protected function setUp(): void
	{
		parent::setUp();
		Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
	}

	protected function tearDown(): void
	{
		foreach ($this->createdUsers as $id)
		{
			foreach (array('#__user_usergroup_map' => 'user_id', '#__users' => 'id') as $table => $column)
			{
				$this->db->setQuery('DELETE FROM '.$table.' WHERE '.$column.'='.(int) $id);
				$this->db->execute();
			}
		}
		$this->createdUsers = array();
	}

	private function notifier($addresses = 'admin@example.org', $userId = -1, $group = -1, $groupEnabled = false)
	{
		return new RecordingNotifier($this->logger, new Repositories($this->logger),
			$addresses, $userId, $group, $groupEnabled);
	}

	private function entry($minutesAgo = 0, $username = 'Admin')
	{
		return (object) array('ipaddress' => self::Ip, 'username' => $username,
			'logtime' => self::minutesAgo($minutesAgo), 'origin' => 0);
	}

	private function failedLogins($count, $minutesAgo)
	{
		for ($i = 0; $i < $count; ++$i)
		{
			$this->insert('#__bfstop_failedlogin', array('ipaddress' => self::Ip, 'logtime' => self::minutesAgo($minutesAgo),
				'username' => 'Admin', 'origin' => 0));
		}
	}

	private function blocks($count, $minutesAgo)
	{
		for ($i = 0; $i < $count; ++$i)
		{
			$this->insert('#__bfstop_bannedip', array('ipaddress' => '198.51.100.'.($i + 1),
				'crdate' => self::minutesAgo($minutesAgo), 'duration' => 60));
		}
	}

	private function createUser($username, $groupId = null, $block = 0)
	{
		$id = $this->insert('#__users', array('name' => $username, 'username' => $username,
			'email' => $username.'@example.org', 'password' => '', 'registerDate' => self::minutesAgo(0),
			'params' => '{}', 'block' => $block), 'id');
		$this->createdUsers[] = $id;
		if ($groupId !== null)
		{
			$this->insert('#__user_usergroup_map', array('user_id' => $id, 'group_id' => $groupId));
		}
		return $id;
	}

	public function testNotificationsAreUnlimitedWithMinusOneAndOffWithZero()
	{
		$this->failedLogins(10, 1);
		$this->blocks(10, 1);
		$notifier = $this->notifier();
		$now = self::minutesAgo(0);
		$this->assertTrue($notifier->isNotificationAllowed($now, -1));
		$this->assertTrue($notifier->isNotificationAllowed($now, -1, true));
		$this->assertFalse($notifier->isNotificationAllowed($now, 0));
		$this->assertFalse($notifier->isNotificationAllowed($now, 0, true));
	}

	public function testFailedLoginNotificationsAreLimitedPerDay()
	{
		$this->failedLogins(3, 1);
		// older than a day: not counted
		$this->failedLogins(5, 25 * 60);
		$notifier = $this->notifier();
		$now = self::minutesAgo(0);
		$this->assertTrue($notifier->isNotificationAllowed($now, 3));
		$this->assertTrue($notifier->isNotificationAllowed($now, 4));
		$this->assertFalse($notifier->isNotificationAllowed($now, 2));
		$this->assertFalse($notifier->isNotificationAllowed($now, 1));
	}

	public function testBlockNotificationsAreLimitedPerDayByTheNumberOfBlocksNotOfFailedLogins()
	{
		$this->blocks(2, 5);
		$this->blocks(4, 3 * 24 * 60);
		$this->failedLogins(20, 1);
		$notifier = $this->notifier();
		$now = self::minutesAgo(0);
		$this->assertTrue($notifier->isNotificationAllowed($now, 2, true));
		$this->assertFalse($notifier->isNotificationAllowed($now, 1, true));
		$this->assertFalse($notifier->isNotificationAllowed($now, 19, false), '20 failed logins');
		$this->assertTrue($notifier->isNotificationAllowed($now, 20, false));
	}

	public function testAFailedLoginIsMailedToEveryAddressInOneMail()
	{
		$notifier = $this->notifier('admin@example.org;ops@example.org');
		$entry = $this->entry();
		$this->failedLogins(1, 0);
		$notifier->failedLogin($entry, -1);

		$this->assertCount(1, $notifier->mails);
		$mail = $notifier->mails[0];
		$this->assertSame(array('admin@example.org', 'ops@example.org'), $mail['to']);
		$this->assertSame($notifier->getFailedLoginBody($entry), $mail['body']);
		$this->assertStringContainsString(self::Ip, $mail['body']);
		$this->assertStringContainsString('Admin', $mail['body']);
		$this->assertSame(Text::sprintf('PLG_SYSTEM_BFSTOP_FAILED_LOGIN_ATTEMPT',
			$notifier->getSiteName(), NotifierHelper::siteAddress()), $mail['subject']);
	}

	public function testNoFailedLoginMailWhenNotificationsAreOff()
	{
		$notifier = $this->notifier();
		$this->failedLogins(1, 0);
		$notifier->failedLogin($this->entry(), 0);
		$this->assertSame(array(), $notifier->mails);
	}

	public function testNoFailedLoginMailOnceTheLimitOfTheDayIsReached()
	{
		$notifier = $this->notifier();
		$this->failedLogins(3, 1);
		$notifier->failedLogin($this->entry(), 2);
		$this->assertSame(array(), $notifier->mails, '3 failed logins today, 2 allowed');
		$notifier->failedLogin($this->entry(), 3);
		$this->assertCount(1, $notifier->mails);
	}

	public function testABlockIsMailedToTheAdministratorsWithTheFailedLoginsWhichCausedIt()
	{
		$this->failedLogins(3, 5);
		$this->blocks(1, 0);
		$notifier = $this->notifier('admin@example.org');
		$entry = $this->entry();
		$failedLogins = (new Repositories($this->logger))->failedLogins()->listUnhandledFromAddress(60, self::Ip,
			$entry->logtime);
		$notifier->blockedNotifyAdmin($entry, $failedLogins, -1);

		$this->assertCount(1, $notifier->mails);
		$mail = $notifier->mails[0];
		$this->assertSame(array('admin@example.org'), $mail['to']);
		$this->assertSame(Text::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_IP_ADDRESS_SUBJECT',
			$notifier->getSiteName(), self::Ip), $mail['subject']);
		$this->assertStringContainsString(self::Ip, $mail['subject']);
		$this->assertSame($notifier->getBlockedBody($entry, $failedLogins), $mail['body']);
		// the table of the failed logins: 2 header lines and one line each
		$list = $notifier->failedLoginList($failedLogins);
		$this->assertSame(3 + 2, substr_count($list, "\n"), "2 header lines + 3 entries:\n".$list);
		$this->assertStringContainsString($list, $mail['body'], 'the failed logins of the address are listed');
	}

	public function testBlockMailsAreLimited()
	{
		$this->blocks(3, 5);
		$notifier = $this->notifier();
		$notifier->blockedNotifyAdmin($this->entry(), array(), 0);
		$notifier->blockedNotifyAdmin($this->entry(), array(), 2);
		$this->assertSame(array(), $notifier->mails, 'off, and 3 blocks today where 2 are allowed');
		$notifier->blockedNotifyAdmin($this->entry(), array(), 3);
		$this->assertCount(1, $notifier->mails);
	}

	public function testTheUnblockMailGoesOnlyToTheUserAndHasTheLink()
	{
		$notifier = $this->notifier('admin@example.org');
		$link = 'https://www.example.org/index.php?option=com_bfstop&token=abc123';
		$notifier->sendUnblockMail('user@example.org', $link);

		$this->assertCount(1, $notifier->mails);
		$mail = $notifier->mails[0];
		$this->assertSame(array('user@example.org'), $mail['to'], 'not the administrators');
		$this->assertStringContainsString($link, $mail['body']);
		$this->assertStringContainsString($notifier->getSiteName(), $mail['body']);
		$this->assertSame(Text::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_SUBJECT', $notifier->getSiteName()), $mail['subject']);
	}

	public function testTheAddressOfAChosenUserIsNotified()
	{
		$id = $this->createUser('notifyuser');
		$notifier = $this->notifier('admin@example.org', $id);
		$this->assertSame(array('admin@example.org', 'notifyuser@example.org'), $notifier->getNotifyAddresses());
		$notifier->blockedNotifyAdmin($this->entry(), array(), -1);
		$this->assertSame(array('admin@example.org', 'notifyuser@example.org'), $notifier->mails[0]['to']);
	}

	public function testTheMembersOfAChosenGroupAreNotifiedIfSwitchedOn()
	{
		$registered = 2; // "Registered", a group of every Joomla! installation
		$this->createUser('groupmember', $registered);
		$this->createUser('notamember');

		$on = $this->notifier('', -1, $registered, true);
		$this->assertContains('groupmember@example.org', $on->getNotifyAddresses());
		$this->assertNotContains('notamember@example.org', $on->getNotifyAddresses());

		$off = $this->notifier('', -1, $registered, false);
		$this->assertSame(array(), $off->getNotifyAddresses());
	}

	public function testDisabledMembersOfTheGroupAreNotNotified()
	{
		$registered = 2;
		$this->createUser('enabledmember', $registered);
		$this->createUser('disabledmember', $registered, 1);
		$addresses = $this->notifier('', -1, $registered, true)->getNotifyAddresses();
		$this->assertContains('enabledmember@example.org', $addresses);
		$this->assertNotContains('disabledmember@example.org', $addresses);
	}

	public function testWithoutAnAddressNothingIsCountedOrMailedOrLoggedAsAnError()
	{
		// the default: no address, no user, no group - but a limit of 5 block
		// notifications. Asking sendMail() to mail nobody logged an error with
		// every block
		$notifier = $this->notifier('');
		$notifier->blockedNotifyAdmin($this->entry(), array(), 5);
		$notifier->failedLogin($this->entry(), -1);
		$this->assertSame(array(), $notifier->mails);
		$this->assertSame(array(), $this->logger->errors);
	}

	public function testAnAddressWhichIsGivenTwiceIsMailedOnce()
	{
		$id = $this->createUser('twice');
		$notifier = $this->notifier('TWICE@example.org', $id);
		$this->assertCount(1, $notifier->getNotifyAddresses());
	}

	/**
	 * A block which may have hit a proxy: the mail says so, with how to lift
	 * the block, and goes to the super users who receive system emails as
	 * well - once to each address, whatever its case, and each in a mail of
	 * its own (nobody sees who else got it).
	 */
	public function testABlockWhichMayHaveHitAProxyWarnsTheSuperUsersToo()
	{
		$this->createUser('sysmail', 8);
		$quiet = $this->createUser('quiet', 8);
		$this->db->setQuery('UPDATE #__users SET '.$this->db->quoteName('sendEmail').' = CASE WHEN id = '.(int) $quiet.' THEN 0 ELSE 1 END WHERE id IN ('.
			implode(',', array_map('intval', $this->createdUsers)).')')->execute();
		$this->createUser('blocked', 8, 1);
		$this->blocks(1, 0);
		$notifier = $this->notifier('notify@example.org;ADMIN@example.org');
		$notifier->blockedNotifyAdmin($this->entry(), array(), -1, true);

		$this->assertCount(3, $notifier->mails, 'one mail per recipient');
		foreach ($notifier->mails as $mail)
		{
			$this->assertCount(1, $mail['to']);
			$this->assertStringContainsString(NotifierHelper::proxyWarning(self::Ip), $mail['body']);
			$this->assertStringContainsString('bfstop:unblock '.self::Ip, $mail['body']);
		}
		$to = array_map(fn ($mail) => strtolower($mail['to'][0]), $notifier->mails);
		sort($to);
		$this->assertSame(array('admin@example.org', 'notify@example.org', 'sysmail@example.org'), $to,
			'the notification addresses and the super users with system emails, nobody twice');

		// without the warning, as before: the notification addresses only
		$notifier = $this->notifier('notify@example.org');
		$notifier->blockedNotifyAdmin($this->entry(), array(), -1);
		$this->assertSame(array('notify@example.org'), $notifier->mails[0]['to']);
		$this->assertStringNotContainsString(NotifierHelper::proxyWarning(self::Ip), $notifier->mails[0]['body']);
	}

	/**
	 * Super users are those Joomla takes for them: also the members of a
	 * group below "Super Users", which inherits core.admin without the
	 * rules of the root asset naming it.
	 */
	public function testTheSuperUsersOfAChildGroupAreWarnedToo()
	{
		$parent = $this->db->setQuery($this->db->createQuery()->select($this->db->quoteName(array('lft', 'rgt')))
			->from($this->db->quoteName('#__usergroups'))->where($this->db->quoteName('id').' = 8'))->loadAssoc();
		$group = $this->insert('#__usergroups', array('parent_id' => 8, 'lft' => (int) $parent['rgt'], 'rgt' => (int) $parent['rgt'],
			'title' => 'Deputy super users'), 'id');
		$helper = new \ReflectionProperty(\Joomla\CMS\Helper\UserGroupsHelper::class, 'instance');
		$helper->setValue(null, null);
		try
		{
			$this->assertContains((int) $group, NotifierHelper::superUserGroups());
			$this->assertContains(8, NotifierHelper::superUserGroups());
			$this->assertNotContains(2, NotifierHelper::superUserGroups(), 'Registered');
			$deputy = $this->createUser('deputy', (int) $group);
			$registered = $this->createUser('registered', 2);
			$this->db->setQuery('UPDATE #__users SET '.$this->db->quoteName('sendEmail').' = 1 WHERE id IN ('.(int) $deputy.', '.(int) $registered.')')->execute();
			$this->blocks(1, 0);
			$notifier = $this->notifier('');
			$notifier->blockedNotifyAdmin($this->entry(), array(), -1, true);
			$to = array_map(fn ($mail) => strtolower($mail['to'][0]), $notifier->mails);
			$this->assertContains('deputy@example.org', $to);
			$this->assertNotContains('registered@example.org', $to);
		}
		finally
		{
			$this->db->setQuery('DELETE FROM #__usergroups WHERE id = '.(int) $group)->execute();
			$helper->setValue(null, null);
		}
	}

	/**
	 * The warning reaches the super users also where nobody is configured to
	 * get BFStop's notifications (the default) - and all of them, if none
	 * receives system emails; still within the limit of block mails a day.
	 */
	public function testTheProxyWarningNeedsNoNotificationAddress()
	{
		$this->blocks(1, 0);
		$notifier = $this->notifier('');
		$this->assertTrue($notifier->mailsBlocks(5, true));
		$this->assertFalse($notifier->mailsBlocks(5, false));
		$this->assertFalse($notifier->mailsBlocks(0, true), '"Notify on blocks": never');
		$notifier->blockedNotifyAdmin($this->entry(), array(), 5, true);
		$this->assertCount(1, $notifier->mails);
		$this->assertSame(array('admin@example.org'), array_map('strtolower', $notifier->mails[0]['to']));

		$this->db->setQuery('UPDATE #__users SET '.$this->db->quoteName('sendEmail').' = 0 WHERE email = '.$this->db->quote('admin@example.org'))->execute();
		try
		{
			$notifier = $this->notifier('');
			$notifier->blockedNotifyAdmin($this->entry(), array(), 5, true);
			$this->assertContains('admin@example.org', array_map('strtolower', $notifier->mails[0]['to']),
				'no super user receives system emails: all of them');
		}
		finally
		{
			$this->db->setQuery('UPDATE #__users SET '.$this->db->quoteName('sendEmail').' = 1 WHERE email = '.$this->db->quote('admin@example.org'))->execute();
		}

		$this->blocks(5, 0);
		$notifier = $this->notifier('');
		$notifier->blockedNotifyAdmin($this->entry(), array(), 5, true);
		$this->assertCount(0, $notifier->mails, 'over the limit of the day');
	}
}
