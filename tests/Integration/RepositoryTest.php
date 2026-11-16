<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Repository\AllowListRepository;
use Codeling\Plugin\System\Bfstop\Repository\BlockRepository;
use Codeling\Plugin\System\Bfstop\Repository\DnsCacheRepository;
use Codeling\Plugin\System\Bfstop\Repository\FailedLoginRepository;
use Codeling\Plugin\System\Bfstop\Repository\FailurePolicy;
use Codeling\Plugin\System\Bfstop\Repository\KnownIpRepository;
use Codeling\Plugin\System\Bfstop\Repository\UnblockTokenRepository;
use Codeling\Plugin\System\Bfstop\Repository\UserRepository;
use Joomla\CMS\Log\Log;
use Joomla\Database\DatabaseDriver;

/**
 * The repositories: that values reach the database as values whatever they
 * contain, and what each does when the database fails (FailurePolicy).
 */
class RepositoryTest extends IntegrationTestCase
{
	// strings which would change a query they were concatenated into
	private const Hostile = array("x' OR '1'='1", "x\\' OR 1=1 -- ", 'x") OR (1=1', "'; DELETE FROM failedlogin; --");

	protected function setUp(): void
	{
		parent::setUp();
		FailurePolicy::reset();
	}

	/**
	 * a database which fails at the first query. A mock of the driver class:
	 * Joomla 5.4's DatabaseInterface doesn't have createQuery() yet.
	 */
	private function brokenDatabase(): DatabaseDriver
	{
		$db = $this->createMock(DatabaseDriver::class);
		$db->method('createQuery')->willThrowException(new \RuntimeException('database is gone'));
		$db->method('setQuery')->willThrowException(new \RuntimeException('database is gone'));
		$db->method('insertObject')->willThrowException(new \RuntimeException('database is gone'));
		return $db;
	}

	/** the errors logged by the failures of the broken database are expected */
	private function expectFailures(int $count)
	{
		$this->assertSame($count, FailurePolicy::failures());
		$this->assertCount($count, $this->logger->errors);
		$this->assertStringContainsString('Database failure in', $this->logger->errors[0]);
		$this->logger->errors = array();
	}

	public function testHostileValuesAreOnlyValues()
	{
		$failed = new FailedLoginRepository($this->db, $this->logger);
		$now = self::minutesAgo(0);
		foreach (self::Hostile as $value)
		{
			$failed->add((object) array('ipaddress' => $value, 'logtime' => $now, 'username' => $value, 'origin' => 0));
			$this->assertSame(1, $failed->countUnhandledFromAddress(60, $value, $now), $value);
			$this->assertSame(1, $failed->countUnhandledForUsername(60, $value, $now), $value);
			$this->assertSame(0, $failed->countUnhandledFromAddress(60, 'x', $now));
			$failed->markHandled($value, $value);
			$this->assertSame(0, $failed->countUnhandledFromAddress(60, $value, $now));
		}
		$this->assertSame(count(self::Hostile), $failed->countInWindow($now, 60), 'none of them deleted anything');

		$users = new UserRepository($this->db, $this->logger);
		$known = new KnownIpRepository($this->db, $this->logger);
		$tokens = new UnblockTokenRepository($this->db, $this->logger);
		foreach (self::Hostile as $value)
		{
			$this->assertFalse($users->accountExists($value), $value);
			$this->assertNull($users->emailByUsername($value));
			$this->assertFalse($known->hasLoggedInFrom('203.0.113.5', $value, 56));
			$this->assertFalse($tokens->hasCurrentFor($value));
			$this->assertFalse($tokens->exists($value));
			$this->assertFalse($tokens->validForBlocks($value, array(1)));
			$known->remember($value, $value);
			$this->assertTrue($known->hasLoggedInFrom($value, $value, 56), $value);
		}
		$this->assertSame(count(self::Hostile), (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip'));
		$dns = new DnsCacheRepository($this->db, $this->logger);
		foreach (self::Hostile as $value)
		{
			$dns->put($value, $value);
			$this->assertSame($value, $dns->get($value, 7));
			$dns->put($value, null);
			$this->assertNull($dns->get($value, 7));
		}
	}

	public function testHostileAddressesDoNotReachTheBlockQueries()
	{
		$blocks = new BlockRepository($this->db, $this->logger);
		$allow = new AllowListRepository($this->db, $this->logger);
		$id = $blocks->add('203.0.113.9', 0);
		$this->assertGreaterThan(0, $id);
		$this->assertSame(array($id), $blocks->activeIdsFor('203.0.113.9'));
		foreach (self::Hostile as $value)
		{
			$this->assertSame(array(), $blocks->activeIdsFor($value), $value);
			$this->assertFalse($allow->contains($value));
			$blocks->recordAttempt(array($id));
		}
		$this->assertSame(array(), $blocks->addressesWithoutActiveBlock());
	}

	public function testLookupsOfAnUnreadableBlockListAreUnknown()
	{
		$blocks = new BlockRepository($this->brokenDatabase(), $this->logger);
		$this->assertNull($blocks->activeIdsFor('203.0.113.9'), 'the caller decides');
		$this->assertNull($blocks->allAddresses());
		$allow = new AllowListRepository($this->brokenDatabase(), $this->logger);
		$this->assertNull($allow->entriesOverlapping('203.0.113.0/24'));
		$this->expectFailures(3);
	}

	public function testWhatGrantsSomethingFailsClosed()
	{
		$db = $this->brokenDatabase();
		$this->assertFalse((new AllowListRepository($db, $this->logger))->contains('203.0.113.9'), 'nothing is allowed');
		$this->assertFalse((new KnownIpRepository($db, $this->logger))->hasLoggedInFrom('203.0.113.9', 'bob', 56), 'no address is trusted');
		$tokens = new UnblockTokenRepository($db, $this->logger);
		$this->assertFalse($tokens->validForBlocks('abc', array(1)), 'no token is valid');
		$this->assertTrue($tokens->hasCurrentFor('bob'), 'no further link is sent');
		$this->assertFalse($tokens->exists('abc'));
		$this->expectFailures(5);
	}

	public function testCountingAndBookkeepingFailOpen()
	{
		$db = $this->brokenDatabase();
		$failed = new FailedLoginRepository($db, $this->logger);
		$now = self::minutesAgo(0);
		$this->assertSame(0, $failed->countUnhandledFromAddress(60, '203.0.113.9', $now), 'nobody is blocked for it');
		$this->assertSame(0, $failed->countUnhandledForUsername(60, 'bob', $now));
		$this->assertNull($failed->unhandledUsernamesFromAddress(60, '203.0.113.9', $now), 'unknown');
		$failed->add((object) array('ipaddress' => '203.0.113.9', 'logtime' => $now, 'username' => 'bob', 'origin' => 0));
		$failed->markHandled('203.0.113.9');
		(new KnownIpRepository($db, $this->logger))->remember('203.0.113.9', 'bob');
		$blocks = new BlockRepository($db, $this->logger);
		$this->assertSame(-1, $blocks->add('203.0.113.9', 0));
		$this->assertSame(0, $blocks->countPrevious('203.0.113.9'));
		$this->assertSame(array(), $blocks->addressesWithoutActiveBlock());
		$this->assertFalse((new DnsCacheRepository($db, $this->logger))->get('203.0.113.9', 7), 'not cached');
		$users = new UserRepository($db, $this->logger);
		$this->assertNull($users->emailById(1));
		$this->assertSame(array(), $users->emailsOfGroup(1));
		$this->expectFailures(12);
	}

	public function testFailuresAreCountedAndTheLastOneIsKept()
	{
		$this->assertSame(0, FailurePolicy::failures());
		$this->assertNull(FailurePolicy::lastFailure());
		(new UserRepository($this->brokenDatabase(), $this->logger))->accountExists('bob');
		$this->assertSame(1, FailurePolicy::failures());
		$this->assertStringContainsString('UserRepository::accountExists: database is gone', FailurePolicy::lastFailure());
		$this->assertTrue($this->logger->hasMessage(Log::ERROR, '(fail-open)'));
		$this->logger->errors = array();
	}
}
