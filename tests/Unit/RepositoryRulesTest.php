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
 * The rules of src/Repository (see Repository): values reach the database
 * as bound parameters, never as part of the SQL; and every failure is
 * handled by FailurePolicy, not by an exception handler of its own. A
 * repository which breaks them is the next SQL injection - or the next
 * lookup whose answer to a database failure nobody decided.
 */
class RepositoryRulesTest extends TestCase
{
	public static function repositoryFiles()
	{
		$files = array();
		foreach (glob(BFSTOP_LIBRARY_ROOT.'/src/Repository/*.php') as $file)
		{
			$files[basename($file)] = array($file);
		}
		return $files;
	}

	public function testThereAreRepositories()
	{
		$this->assertGreaterThanOrEqual(10, count(self::repositoryFiles()));
	}

	#[DataProvider('repositoryFiles')]
	public function testValuesAreBoundNotQuoted($file)
	{
		$code = file_get_contents($file);
		$this->assertDoesNotMatchRegularExpression('/->(quote|escape)\(/', $code,
			'a value is put into the SQL: bind it (bindValues(), whereIn())');
		// a variable concatenated into the SQL handed to the database
		$this->assertDoesNotMatchRegularExpression('/->setQuery\(\s*[\'"][^;]*[\'"]\s*\.\s*\$/', $code,
			'a variable is put into the SQL: bind it');
	}

	#[DataProvider('repositoryFiles')]
	public function testQueriesAreRunByTheBaseClassOnly($file)
	{
		if (basename($file) === 'Repository.php')
		{
			$this->assertStringContainsString('->db->setQuery(', file_get_contents($file), 'the base class runs them');
			return;
		}
		$this->assertDoesNotMatchRegularExpression('/->db->(setQuery|execute|load[A-Za-z]+)\(/', file_get_contents($file),
			'run the query with execute(), scalar(), count(), column(), row() or objects() of Repository');
	}

	#[DataProvider('repositoryFiles')]
	public function testFailuresAreHandledByThePolicy($file)
	{
		$code = file_get_contents($file);
		if (basename($file) === 'FailurePolicy.php')
		{
			$this->assertStringContainsString('catch (\Exception', $code, 'the policy is where failures are caught');
			return;
		}
		$this->assertStringNotContainsString('catch (', $code,
			'a failure is handled with failOpen(), failClosed() or unknown(), see FailurePolicy');
	}
}
