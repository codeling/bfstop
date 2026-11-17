<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Joomla\CMS\Factory;

/**
 * How many queries the plugin sends for what every visitor causes: a page
 * view, a request of a blocked address, a failed login. Each of them runs on
 * every request of that kind, so one more is a cost to the whole site - and,
 * for the failed logins, a way for an attacker to make the site do more work
 * per request. The numbers are the plugin's own queries (the scripts of
 * fixtures/ start counting when they hand the event to the plugin), the same
 * on every database - except that Joomla's lookups of a table's columns are
 * not counted (see queriesOf()). They are limits, not exact numbers: a change
 * which needs more queries has to say so by raising one - and which ones.
 *
 * The performance comparison (tests/performance) measures what it costs.
 */
class QueryCountTest extends IntegrationTestCase
{
	private const Ip = '203.0.113.61';

	// the most queries of each kind; see testQueriesPerRequestStayWithinTheirLimits
	private const Limits = array(
		'page view' => 2,
		'blocked request' => 3,
		'failed login, unknown user' => 6,
		'failed login, account' => 6,
		'failed login which blocks' => 16,
	);

	private static $originalParams;
	private static $kinds = null;
	private $createdUsers = array();

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
		$db->setQuery("SELECT params FROM #__extensions WHERE type='component' AND element='com_bfstop'");
		self::$originalParams = $db->loadResult();
	}

	public static function tearDownAfterClass(): void
	{
		if (self::$originalParams !== null)
		{
			$db = Factory::getContainer()->get(\Joomla\Database\DatabaseInterface::class);
			self::storeSettings($db, self::$originalParams);
		}
	}

	protected function setUp(): void
	{
		parent::setUp();
		$this->configure();
	}

	protected function tearDown(): void
	{
		foreach ($this->createdUsers as $id)
		{
			$this->db->setQuery('DELETE FROM #__users WHERE id='.(int) $id);
			$this->db->execute();
		}
	}

	private function configure(array $params = array())
	{
		$this->setSettings(json_encode($params + array(
			'blockMode' => 'full',
			'blockNumber' => 15,
			'riskMinBlockNumber' => 1,
			'riskBlockNumberReductionPerPoint' => 0,
			'riskDelaySecondsPerPoint' => 0,
			'checkInterval' => 60,
			'blockDuration' => 60,
			'delayDuration' => 0,
			'accountThrottleEnabled' => 0,
			'notifyBlockedNumber' => 0,
			'logLevel' => 8, // errors only
		)));
		// the daily maintenance (purging, trimming - a score of queries) is the task of
		// the Task Scheduler, or of a request if it didn't run for two days: it just
		// ran, so no request in the counts does it
		$this->markMaintenanceDone();
	}

	private function createUser($username)
	{
		$this->createdUsers[] = $this->insert('#__users', array('name' => $username, 'username' => $username,
			'email' => $username.'@example.org', 'password' => '', 'registerDate' => self::minutesAgo(0),
			'params' => '{}'), 'id');
	}

	/**
	 * Runs a fixture script with --count-queries.
	 *
	 * @return string[] the queries the plugin sent
	 */
	private function queriesOf($script, array $arguments)
	{
		$command = escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/fixtures/'.$script).' '.
			implode(' ', array_map('escapeshellarg', array_merge($arguments, array('--count-queries')))).' 2>&1';
		exec($command, $lines, $exitCode);
		$output = implode("\n", $lines);
		$this->assertSame(0, $exitCode, $output);
		$queries = array();
		$counted = 0;
		foreach ($lines as $line)
		{
			if (strncmp($line, 'QUERY: ', 7) !== 0)
			{
				continue;
			}
			++$counted;
			// insertObject() has Joomla look up the columns of its table first, once for
			// each table in a request: one query on MySQL and MariaDB, two on
			// PostgreSQL. The driver's business, which differs between databases.
			if (!preg_match('/^SHOW FULL COLUMNS|current_schemas\(|pg_catalog\.pg_attribute/', substr($line, 7)))
			{
				$queries[] = substr($line, 7);
			}
		}
		$this->assertMatchesRegularExpression('/^QUERIES: '.$counted.'$/m', $output);
		return $queries;
	}

	private function failedLogin($username, $ip = self::Ip)
	{
		return $this->queriesOf('failed_login.php', array($ip, $username, '--live-site=https://www.example.org'));
	}

	private function pageView($ip = self::Ip)
	{
		return $this->queriesOf('request.php', array($ip, ''));
	}

	/** every kind of request which has a limit, with its queries (made once) */
	private function allKinds()
	{
		if (self::$kinds !== null)
		{
			return self::$kinds;
		}
		$kinds = array();
		$kinds['page view'] = $this->pageView();

		$this->insert('#__bfstop_bannedip', array('ipaddress' => '203.0.113.62', 'crdate' => self::minutesAgo(0), 'duration' => 60));
		$kinds['blocked request'] = $this->pageView('203.0.113.62');

		$kinds['failed login, unknown user'] = $this->failedLogin('nobody-by-this-name');

		$this->createUser('QueryCountUser');
		$kinds['failed login, account'] = $this->failedLogin('QueryCountUser', '203.0.113.63');

		// the failed login which gets an address blocked, after attempts against many
		// other usernames; the user is told (notifyBlockedUser), which has to find out
		// whether any of those usernames is an account
		$this->configure(array('blockNumber' => 30, 'notifyBlockedUser' => 2));
		for ($i = 0; $i < 29; ++$i)
		{
			$this->insert('#__bfstop_failedlogin', array('username' => 'other'.$i, 'ipaddress' => '203.0.113.64',
				'logtime' => self::minutesAgo(1), 'origin' => 0, 'handled' => 0));
		}
		$kinds['failed login which blocks'] = $this->failedLogin('QueryCountUser', '203.0.113.64');
		$this->assertSame(1, (int) $this->queryValue("SELECT COUNT(*) FROM #__bfstop_bannedip WHERE ipaddress='203.0.113.64'"),
			'the last failed login blocks the address');
		return self::$kinds = $kinds;
	}

	private function onUsers($sql)
	{
		return stripos($sql, $this->db->getPrefix().'users') !== false;
	}

	public function testQueriesPerRequestStayWithinTheirLimits()
	{
		foreach ($this->allKinds() as $kind => $queries)
		{
			$this->assertLessThanOrEqual(self::Limits[$kind], count($queries),
				$kind.' sends '.count($queries)." queries:\n".implode("\n", $queries));
			// a limit which is not reached any more would hide the next query added
			$this->assertGreaterThanOrEqual(self::Limits[$kind], count($queries),
				'lower the limit of "'.$kind.'" to '.count($queries).":\n".implode("\n", $queries));
		}
	}

	public function testNoLookupByUsernameLowersTheColumn()
	{
		// LOWER(username) = ... can't use an index: the table is read in full. The
		// tables with a lower case column have it for this, and MySQL and MariaDB
		// compare the accounts' names case-insensitively themselves. PostgreSQL
		// compares exactly: for the accounts there is no other way there.
		$postgres = $this->db->getServerType() === 'postgresql';
		foreach ($this->allKinds() as $kind => $queries)
		{
			foreach ($queries as $sql)
			{
				if ($postgres && $this->onUsers($sql))
				{
					continue;
				}
				$this->assertDoesNotMatchRegularExpression('/LOWER\s*\(\s*[`"]?(?:\w+[`"]?\.[`"]?)?(username|email)[`"]?\s*\)/i', $sql,
					$kind.': a lookup lowers a column');
			}
		}
	}

	public function testTheUsernamesOfABlockAreLookedUpInOneQuery()
	{
		// not one query per username the failed logins of the address were against: one
		// for all of them, and one for the name of the login itself
		$lookups = array_filter($this->allKinds()['failed login which blocks'], function ($sql)
		{
			return $this->onUsers($sql) && stripos($sql, 'SELECT 1 FROM') === 0;
		});
		$this->assertLessThanOrEqual(2, count($lookups), implode("\n", $lookups));
	}

	public function testTheFailedLoginsOfTheAddressAreCountedOnce()
	{
		// for the message of the remaining attempts (shown by default, see
		// notifyUsePasswordReminder) and for the decision to block: one count
		foreach ($this->allKinds() as $kind => $queries)
		{
			if (strpos($kind, 'failed login') !== 0)
			{
				continue;
			}
			$counts = array_filter($queries, function ($sql)
			{
				return stripos($sql, 'SELECT COUNT(') === 0 && strpos($sql, $this->db->getPrefix().'bfstop_failedlogin') !== false &&
					preg_match('/[`"]ipaddress[`"]\s*=/', $sql);
			});
			$this->assertCount(1, $counts, $kind.":\n".implode("\n", $counts));
		}
	}
}
