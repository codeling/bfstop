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
		$this->rotated = $logPath.'/plg_system_bfstop.1.log.php';
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
}
