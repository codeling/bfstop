<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Library\Bfstop\Helper\LockHelper;
use PHPUnit\Framework\TestCase;

class LockHelperTest extends TestCase
{
	private $file;

	protected function setUp(): void
	{
		$this->file = sys_get_temp_dir().'/bfstop-locktest-'.bin2hex(random_bytes(6)).'.lock';
	}

	protected function tearDown(): void
	{
		@unlink($this->file);
	}

	public function testDueOnceInTheInterval()
	{
		$this->assertTrue(LockHelper::due($this->file, 3600), 'never done');
		$this->assertFileExists($this->file, 'the stamp is written');
		$this->assertFalse(LockHelper::due($this->file, 3600), 'done just now');
		touch($this->file, time() - 3600);
		$this->assertTrue(LockHelper::due($this->file, 3600), 'the interval is over');
		$this->assertFalse(LockHelper::due($this->file, 3600));
		// a stamp from the future (the clock was set back) doesn't silence it
		touch($this->file, time() + 7200);
		$this->assertTrue(LockHelper::due($this->file, 3600));
	}

	public function testDueWhereTheStampCantBeWritten()
	{
		$file = sys_get_temp_dir().'/bfstop-no-such-directory-'.bin2hex(random_bytes(6)).'/x.stamp';
		$this->assertTrue(LockHelper::due($file, 3600));
		$this->assertTrue(LockHelper::due($file, 3600), 'always: there is nothing to tell it was done');
	}

	public function testLockIsExclusiveUntilReleased()
	{
		$first = LockHelper::acquire($this->file, 0);
		$this->assertIsResource($first);
		$this->assertFileExists($this->file, 'the file is created');
		// another handle is somebody else to flock(), also within one process
		$this->assertNull(LockHelper::acquire($this->file, 0), 'held');
		LockHelper::release($first);
		$second = LockHelper::acquire($this->file, 0);
		$this->assertIsResource($second, 'free again');
		LockHelper::release($second);
	}

	public function testWaitingForAHeldLockEnds()
	{
		$held = LockHelper::acquire($this->file, 0);
		$start = microtime(true);
		$this->assertNull(LockHelper::acquire($this->file, 0.3));
		$waited = microtime(true) - $start;
		$this->assertGreaterThanOrEqual(0.3, $waited, 'waits for it');
		$this->assertLessThan(2, $waited, 'but not for ever');
		LockHelper::release($held);
	}

	public function testWaitsUntilTheLockIsReleased()
	{
		// a child process holds the lock for a moment
		$child = proc_open(array(PHP_BINARY, '-r',
			'$h = fopen($argv[1], "c"); flock($h, LOCK_EX); echo "LOCKED\n"; usleep(400000);', $this->file),
			array(1 => array('pipe', 'w')), $pipes);
		$this->assertSame("LOCKED\n", fgets($pipes[1]));
		$start = microtime(true);
		$handle = LockHelper::acquire($this->file, 10);
		$waited = microtime(true) - $start;
		$this->assertIsResource($handle, 'taken once the other let go of it');
		$this->assertGreaterThan(0.2, $waited);
		$this->assertLessThan(5, $waited, 'as soon as it was free, not when the time was up');
		LockHelper::release($handle);
		fclose($pipes[1]);
		proc_close($child);
	}

	public function testFileWhichCannotBeOpened()
	{
		$this->assertFalse(LockHelper::acquire(sys_get_temp_dir().'/bfstop-no-such-dir-'.bin2hex(random_bytes(6)).'/x.lock', 0));
	}

	public function testReleaseTakesWhateverAcquireReturned()
	{
		LockHelper::release(null);
		LockHelper::release(false);
		$this->addToAssertionCount(1);
	}
}
