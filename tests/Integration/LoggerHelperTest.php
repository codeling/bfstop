<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use Joomla\CMS\Factory;

class LoggerHelperTest extends IntegrationTestCase
{
	private $file;
	private $rotated;
	private $backup;

	protected function setUp(): void
	{
		parent::setUp();
		$logPath = Factory::getApplication()->get('log_path');
		$this->file = $logPath.'/'.LoggerHelper::LogFile;
		$this->rotated = $logPath.'/'.LoggerHelper::RotatedLogFile;
		$this->backup = array();
		foreach (array($this->file, $this->rotated) as $file)
		{
			$this->backup[$file] = is_file($file) ? file_get_contents($file) : null;
			@unlink($file);
		}
	}

	protected function tearDown(): void
	{
		foreach ($this->backup as $file => $content)
		{
			@unlink($file);
			if ($content !== null)
			{
				file_put_contents($file, $content);
			}
		}
	}

	public function testBigLogFileIsRotated()
	{
		file_put_contents($this->file, str_repeat('x', LoggerHelper::MaxLogFileBytes + 1));
		new LoggerHelper(8);
		$this->assertFileDoesNotExist($this->file);
		$this->assertSame(LoggerHelper::MaxLogFileBytes + 1, filesize($this->rotated));
		$this->assertStringEndsWith('.php', $this->rotated, 'must stay a PHP file, not served as text');
	}

	public function testSmallLogFileIsKept()
	{
		file_put_contents($this->file, 'small');
		new LoggerHelper(8);
		$this->assertSame('small', file_get_contents($this->file));
		$this->assertFileDoesNotExist($this->rotated);
	}

	public function testOnlyOnePreviousGenerationIsKept()
	{
		file_put_contents($this->rotated, 'older');
		file_put_contents($this->file, str_repeat('y', 100));
		LoggerHelper::rotateIfTooBig(50);
		$this->assertSame(str_repeat('y', 100), file_get_contents($this->rotated));
	}

	public function testDisabledLoggingDoesntTouchTheFile()
	{
		file_put_contents($this->file, str_repeat('x', LoggerHelper::MaxLogFileBytes + 1));
		new LoggerHelper(LoggerHelper::Disabled);
		$this->assertFileExists($this->file);
	}

	public function testSizeLimitIsConfigurable()
	{
		file_put_contents($this->file, str_repeat('x', 2000));
		new LoggerHelper(8, 1000);
		$this->assertFileDoesNotExist($this->file);
		$this->assertFileExists($this->rotated);
		file_put_contents($this->file, str_repeat('x', 2000));
		new LoggerHelper(8, 5000);
		$this->assertFileExists($this->file);
	}

	public function testSizeLimitFromSetting()
	{
		$this->assertSame(3 * 1048576, LoggerHelper::maxBytesFromMegabytes(3));
		$this->assertSame(LoggerHelper::MaxLogFileBytes, LoggerHelper::maxBytesFromMegabytes(0));
		$this->assertSame(LoggerHelper::MaxLogFileBytes, LoggerHelper::maxBytesFromMegabytes(-2));
	}

	private static function entry($daysAgo, $message)
	{
		return gmdate('c', time() - $daysAgo * 86400 - 60).' INFO '.$message."\n";
	}

	private static function header()
	{
		return "#<?php die('Forbidden.'); ?>\n#Date: 2021-09-17 08:50:26 UTC\n#Software: Joomla\n\n".
			"#Fields: datetime\tpriority\tmessage\n\n";
	}

	public function testPruneRemovesOldEntriesOnly()
	{
		file_put_contents($this->file, self::header().
			self::entry(40, 'ancient').
			"continuation of the ancient entry\n".
			self::entry(29, 'old').
			self::entry(27, 'recent').
			"continuation of the recent entry\n".
			self::entry(0, 'new'));
		$this->assertSame(2, LoggerHelper::pruneByAge(28));
		$this->assertSame(self::header().
			self::entry(27, 'recent').
			"continuation of the recent entry\n".
			self::entry(0, 'new'),
			file_get_contents($this->file));
	}

	public function testPruneAlsoCoversThePreviousGeneration()
	{
		file_put_contents($this->rotated, self::header().self::entry(100, 'ancient'));
		file_put_contents($this->file, self::header().self::entry(1, 'new'));
		$this->assertSame(1, LoggerHelper::pruneByAge(28));
		$this->assertSame(self::header(), file_get_contents($this->rotated));
		$this->assertSame(self::header().self::entry(1, 'new'), file_get_contents($this->file));
	}

	public function testPruneWithoutAgeKeepsEverything()
	{
		$content = self::header().self::entry(400, 'ancient');
		file_put_contents($this->file, $content);
		$this->assertSame(0, LoggerHelper::pruneByAge(0));
		$this->assertSame($content, file_get_contents($this->file));
	}

	public function testPruneWithoutLogFileIsFine()
	{
		$this->assertSame(0, LoggerHelper::pruneByAge(28));
		$this->assertFileDoesNotExist($this->file);
	}

	public function testPruneWorksWhileLoggingIsDisabled()
	{
		file_put_contents($this->file, self::header().self::entry(40, 'ancient'));
		new LoggerHelper(LoggerHelper::Disabled);
		$this->assertSame(1, LoggerHelper::pruneByAge(28));
		$this->assertSame(self::header(), file_get_contents($this->file));
	}

	public function testDeleteLogFiles()
	{
		file_put_contents($this->file, 'a');
		file_put_contents($this->rotated, 'b');
		$this->assertSame(2, LoggerHelper::deleteLogFiles());
		$this->assertFileDoesNotExist($this->file);
		$this->assertFileDoesNotExist($this->rotated);
		$this->assertSame(0, LoggerHelper::deleteLogFiles());
	}
}
