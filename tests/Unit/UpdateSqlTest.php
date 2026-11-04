<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * An update which stopped halfway leaves the schema version where it was, so
 * the next attempt runs the whole update file again: a statement which fails
 * on a table it already changed would stop every later attempt as well. The
 * MySQL statements which can't be written to work a second time have to be
 * marked "CAN FAIL" (see sql/updates/2.0.0.sql); the update files of earlier
 * versions predate that.
 */
class UpdateSqlTest extends TestCase
{
	private const Marker = '/** CAN FAIL **/';

	// ALTER TABLE changes which fail if they were made before
	private const NotRepeatable = '/\b(ADD\s+(COLUMN|INDEX|KEY|UNIQUE|CONSTRAINT|PRIMARY|FULLTEXT)|DROP\s+(COLUMN|INDEX|KEY|PRIMARY|FOREIGN)|RENAME\s+(COLUMN|INDEX|KEY|TO))\b/i';

	public static function updateFiles(): array
	{
		$files = array();
		foreach (glob(dirname(__DIR__, 2).'/sql/updates/*.sql') as $file)
		{
			if (version_compare(basename($file, '.sql'), '2.0.0', '>='))
			{
				$files[basename($file)] = array($file);
			}
		}
		return $files;
	}

	private static function statements($file)
	{
		$sql = preg_replace('/^\s*--.*$/m', '', file_get_contents($file));
		return array_filter(array_map('trim', explode(';', $sql)), 'strlen');
	}

	#[DataProvider('updateFiles')]
	public function testStatementsWhichCanOnlyRunOnceAreMarkedCanFail($file)
	{
		foreach (self::statements($file) as $statement)
		{
			if (preg_match(self::NotRepeatable, $statement))
			{
				$this->assertStringEndsWith(self::Marker, $statement,
					basename($file).": fails if run again, mark it CAN FAIL: $statement");
			}
		}
	}

	#[DataProvider('updateFiles')]
	public function testTablesAreCreatedOnlyIfTheyDontExist($file)
	{
		foreach (self::statements($file) as $statement)
		{
			if (preg_match('/^CREATE\s+TABLE\b/i', $statement))
			{
				$this->assertMatchesRegularExpression('/^CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\b/i', $statement,
					basename($file));
			}
		}
	}

	public function testTheMarkerIsWhereJoomlaLooksForIt()
	{
		// Installer::parseSchemaUpdates() only recognises it right before the
		// semicolon which ends the statement
		$marked = 0;
		foreach (self::updateFiles() as list($file))
		{
			$sql = preg_replace('/^\s*--.*$/m', '', file_get_contents($file));
			$marked += substr_count($sql, self::Marker);
			$this->assertSame(substr_count($sql, self::Marker), substr_count($sql, ' '.self::Marker.';'), basename($file));
		}
		$this->assertGreaterThan(0, $marked);
	}
}
