<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Library\Bfstop\Helper\LockHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\DailyMaintenance;
use Codeling\Library\Bfstop\Service\MaintenanceSchedule;
use Joomla\Database\QueryMonitorInterface;
use Joomla\Registry\Registry;

/**
 * The daily maintenance: when it is due (MaintenanceSchedule), what it does
 * (DailyMaintenance), and that Joomla's Task Scheduler runs it through the
 * task plugin.
 */
class MaintenanceTest extends IntegrationTestCase
{
	private Repositories $repos;
	private MaintenanceSchedule $schedule;

	protected function setUp(): void
	{
		parent::setUp();
		$this->repos = new Repositories($this->logger);
		$this->schedule = new MaintenanceSchedule($this->repos->state());
	}

	private function lastMaintenance()
	{
		$value = $this->queryValue("SELECT value FROM #__bfstop_state WHERE name='lastMaintenance'");
		return $value === null ? null : (int) $value;
	}

	/** an entry which the maintenance purges: a known address nobody logged in from for a year */
	private function staleEntry()
	{
		$this->insert('#__bfstop_knownip', array('ipaddress' => '203.0.113.1', 'username' => 'bob',
			'first_success' => self::minutesAgo(400 * 1440 + 1), 'last_success' => self::minutesAgo(400 * 1440)));
	}

	private function staleEntries()
	{
		return (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_knownip');
	}

	public function testStateRemembersValues()
	{
		$state = $this->repos->state();
		$this->assertNull($state->get('nothing'));
		$this->assertSame('x', $state->get('nothing', 'x'));
		$state->set('a', 1700000000);
		$this->assertSame('1700000000', $state->get('a'));
		$state->set('a', 2);
		$state->set('b', 'text');
		$this->assertSame('2', $state->get('a'), 'replaced, not added');
		$this->assertSame('text', $state->get('b'));
		$this->assertSame(2, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_state'));
		$state->set('a', 2);
		$this->assertSame('2', $state->get('a'), 'the same value again');
	}

	public function testMaintenanceWhichNeverRanIsOverdue()
	{
		$this->assertTrue($this->schedule->fallbackDue());
	}

	public function testRecordedRunIsInTheStateAndTheStamp()
	{
		$now = time();
		$this->schedule->recordRun($now - 100);
		$this->assertSame($now - 100, $this->lastMaintenance());
		$this->assertEqualsWithDelta($now - 100, filemtime(MaintenanceSchedule::stampFile()), 1);
		$this->assertFalse($this->schedule->fallbackDue($now));
	}

	public function testAskingWhetherItIsOverdueCostsNoQuery()
	{
		// every request asks
		$this->schedule->recordRun();
		$counter = new class implements QueryMonitorInterface {
			public int $queries = 0;
			public function startQuery(string $sql, ?array $boundParams = null): void { ++$this->queries; }
			public function stopQuery(): void {}
		};
		$db = $this->db;
		$db->setMonitor($counter);
		try
		{
			$this->assertFalse($this->schedule->fallbackDue());
			$this->assertFalse($this->schedule->fallbackDue());
		}
		finally
		{
			$db->setMonitor(null);
		}
		$this->assertSame(0, $counter->queries);
	}

	public function testItIsOverdueAfterTwoDays()
	{
		$now = time();
		$this->schedule->recordRun($now - MaintenanceSchedule::FallbackAfter + 60);
		$this->assertFalse($this->schedule->fallbackDue($now), 'a minute short of two days');
		$this->schedule->recordRun($now - MaintenanceSchedule::FallbackAfter - 60);
		$this->assertTrue($this->schedule->fallbackDue($now), 'a minute over');
	}

	public function testAMissingStampIsMadeFromTheState()
	{
		// a temporary directory which was emptied: the state table is the authority
		$now = time();
		$this->schedule->recordRun($now - 3600);
		unlink(MaintenanceSchedule::stampFile());
		$this->assertFalse($this->schedule->fallbackDue($now));
		$this->assertEqualsWithDelta($now - 3600, filemtime(MaintenanceSchedule::stampFile()), 1, 'made again');

		$this->schedule->recordRun($now - 3 * 86400);
		unlink(MaintenanceSchedule::stampFile());
		$this->assertTrue($this->schedule->fallbackDue($now), 'and overdue by it');
	}

	public function testItIsRunIfOverdueOnly()
	{
		$settings = new Registry(array('deleteOld' => 4));
		$maintenance = new DailyMaintenance($this->repos, $settings);
		$this->staleEntry();
		$this->schedule->recordRun(time() - 3600);
		$this->assertFalse($maintenance->runIfOverdue());
		$this->assertSame(1, $this->staleEntries());
		$this->schedule->recordRun(time() - 3 * 86400);
		$this->assertTrue($maintenance->runIfOverdue());
		$this->assertSame(0, $this->staleEntries());
		$this->assertGreaterThan(time() - 60, $this->lastMaintenance());
		$this->assertFalse($maintenance->runIfOverdue(), 'not again');
	}

	public function testItIsNotRunWhileAnotherRequestRunsIt()
	{
		$settings = new Registry(array('deleteOld' => 4));
		$maintenance = new DailyMaintenance($this->repos, $settings);
		$this->staleEntry();
		$lockFile = LockHelper::file('maintenance');
		$handle = LockHelper::acquire($lockFile, 0);
		$this->assertIsResource($handle, 'the test is "the other request"');
		try
		{
			$this->assertFalse($maintenance->runNow());
			$this->assertSame(1, $this->staleEntries(), 'nothing was done');
			$this->assertNull($this->lastMaintenance());
		}
		finally
		{
			LockHelper::release($handle);
		}
		$this->assertTrue($maintenance->runNow());
		$this->assertSame(0, $this->staleEntries());
	}

	public function testItPurgesByAgeOnlyIfThatIsSet()
	{
		$this->insert('#__bfstop_failedlogin', array('username' => 'old', 'ipaddress' => '203.0.113.9',
			'logtime' => self::minutesAgo(30 * 1440), 'origin' => 0, 'handled' => 0));
		(new DailyMaintenance($this->repos, new Registry(array('deleteOld' => 0))))->runNow();
		$this->assertSame(1, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'), 'purge age 0: none');
		(new DailyMaintenance($this->repos, new Registry(array('deleteOld' => 4))))->runNow();
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_failedlogin'), 'older than 4 weeks');
	}

	public function testTheTaskSchedulerRunsTheMaintenance()
	{
		// the way a site runs it: Joomla's scheduler on the command line (a web cron job
		// and the lazy scheduler start the same task), against the installed task plugin
		$script = require_once dirname(__DIR__, 2).'/task/script.php';
		$this->db->setQuery("DELETE FROM #__scheduler_tasks WHERE type='bfstop.maintenance'")->execute();
		$this->assertTrue(\PlgtaskbfstopInstallerScript::createTask($this->db));
		$id = (int) $this->queryValue("SELECT id FROM #__scheduler_tasks WHERE type='bfstop.maintenance'");
		$this->staleEntry();
		$this->assertNull($this->lastMaintenance());

		exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg(getenv('JOOMLA_ROOT').'/cli/joomla.php').
			' scheduler:run --id='.$id.' 2>&1', $output, $exitCode);
		$output = implode("\n", $output);
		$this->assertSame(0, $exitCode, $output);

		$this->assertSame(0, $this->staleEntries(), "the task did the maintenance:\n".$output);
		$this->assertGreaterThan(time() - 120, $this->lastMaintenance());
		$task = $this->db->setQuery('SELECT * FROM #__scheduler_tasks WHERE id='.$id)->loadObject();
		$this->assertSame(1, (int) $task->times_executed, $output);
		$this->assertSame(0, (int) $task->times_failed);
		$this->assertSame(0, (int) $task->last_exit_code);
		$this->assertNotNull($task->last_execution);
		// and the next run is a day from now, not due again
		$this->assertGreaterThan(time() + 20 * 3600, strtotime($task->next_execution.' UTC'));
		// no request has to do it for the next two days
		$this->assertFalse($this->schedule->fallbackDue());
	}
}
