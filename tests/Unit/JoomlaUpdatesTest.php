<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__).'/ci/joomla-updates.php';

/**
 * tests/ci/joomla-updates.php decides which Joomla! releases the weekly
 * workflow proposes: patch releases of the matrix' versions are taken over,
 * newer minor/major lines are only reported.
 */
class JoomlaUpdatesTest extends TestCase
{
	private const Workflow = "      matrix:\n        include:\n"
		."          - { joomla: 5.4.8, php: '8.2', db: 'mysql:8.0' }\n"
		."          - { joomla: 5.4.8, php: '8.2', db: 'postgres:12' }\n"
		."          - { joomla: 6.1.3, php: '8.4', db: 'mysql:8.4' }\n";

	private const Hash8 = '2c9dc7e6f451c83c43bbb7eb5c9348cb889ba802b72915c5bbd899f9d2de3f3d';
	private const Hash13 = '184f8c582cde5981693de7c28547c6e834c48c50cb377c7b8421bbfd33bbdf6f';
	private const Hash9 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

	private const Checksums = "# header\n#\n"
		."#  5.4.8  MD5 and SHA1 equal those on downloads.joomla.org/cms/joomla5/5-4-8\n"
		."#  6.1.3  taken from the GitHub release asset (Joomla's page for the version\n"
		."#         could not be consulted); check it against downloads.joomla.org\n"
		."2c9dc7e6f451c83c43bbb7eb5c9348cb889ba802b72915c5bbd899f9d2de3f3d  Joomla_5.4.8-Stable-Full_Package.tar.gz\n"
		."184f8c582cde5981693de7c28547c6e834c48c50cb377c7b8421bbfd33bbdf6f  Joomla_6.1.3-Stable-Full_Package.tar.gz\n";

	private static function release($tag, $options = array())
	{
		$digest = array_key_exists('digest', $options) ? $options['digest'] : 'sha256:'.str_repeat('b', 64);
		$asset = array('name' => "Joomla_$tag-Stable-Full_Package.tar.gz");
		if ($digest !== null)
		{
			$asset['digest'] = $digest;
		}
		return array(
			'tag_name' => $tag,
			'draft' => $options['draft'] ?? false,
			'prerelease' => $options['prerelease'] ?? false,
			'assets' => ($options['assets'] ?? true) ? array(array('name' => 'other.zip'), $asset) : array(),
		);
	}

	public function testMatrixVersions()
	{
		$this->assertSame(array('5.4.8', '6.1.3'), matrixVersions(self::Workflow));
	}

	public function testStableReleasesIgnoreDraftsPrereleasesOddTagsAndMissingPackages()
	{
		$stable = stableReleases(array(
			self::release('6.1.4'),
			self::release('6.2.0', array('prerelease' => true)),
			self::release('6.2.0-beta1'),
			self::release('6.3.0', array('draft' => true)),
			self::release('5.4.9', array('assets' => false)),
			self::release('3.10.12-elts'),
			self::release('5.4.10', array('digest' => null)),
			array('tag_name' => '5.4.11', 'assets' => array(array('name' => 'Joomla_5.4.12-Stable-Full_Package.tar.gz'))),
		));
		$this->assertSame(array('6.1.4' => str_repeat('b', 64), '5.4.10' => ''), $stable);
	}

	public function testPatchReleaseIsABumpOfItsLineOnly()
	{
		$stable = array('5.4.8' => '', '5.4.9' => 'x', '5.4.10' => 'y', '6.1.3' => '', '6.0.9' => 'z');
		$plan = plan(array('5.4.8', '6.1.3'), $stable);
		$this->assertSame(array(array('from' => '5.4.8', 'to' => '5.4.10', 'digest' => 'y')), $plan['bumps']);
		$this->assertSame(array(), $plan['new_lines'], 'older lines (6.0) are not news');
	}

	public function testNewerLinesAreOnlyReportedOncePerLine()
	{
		$stable = array('5.4.8' => '', '6.1.3' => '', '6.1.4' => 'a', '6.2.0' => 'b', '6.2.1' => 'c', '7.0.0' => 'd');
		$plan = plan(array('5.4.8', '6.1.3'), $stable);
		$this->assertSame(array(array('from' => '6.1.3', 'to' => '6.1.4', 'digest' => 'a')), $plan['bumps']);
		$this->assertSame(array(
			array('line' => '6.2', 'version' => '6.2.1'),
			array('line' => '7.0', 'version' => '7.0.0'),
		), $plan['new_lines']);
	}

	public function testNothingToDoWhenCurrent()
	{
		$plan = plan(array('5.4.8', '6.1.3'), array('5.4.8' => '', '6.1.3' => '', '5.3.0' => ''));
		$this->assertSame(array(), $plan['bumps']);
		$this->assertSame(array(), $plan['new_lines']);
	}

	public function testApplyReplacesTheVersionAndAddsTheChecksum()
	{
		list($workflow, $checksums) = apply(self::Workflow, self::Checksums, '5.4.8', '5.4.9', self::Hash9);
		$this->assertSame(0, substr_count($workflow, '5.4.8'));
		$this->assertSame(2, substr_count($workflow, 'joomla: 5.4.9,'));
		$this->assertSame(1, substr_count($workflow, 'joomla: 6.1.3,'));

		$lines = explode("\n", rtrim($checksums));
		$this->assertContains(self::Hash8.'  Joomla_5.4.8-Stable-Full_Package.tar.gz', $lines, 'the old entry stays');
		$this->assertContains(self::Hash9.'  Joomla_5.4.9-Stable-Full_Package.tar.gz', $lines);
		$this->assertLessThan(
			array_search(self::Hash13.'  Joomla_6.1.3-Stable-Full_Package.tar.gz', $lines),
			array_search(self::Hash9.'  Joomla_5.4.9-Stable-Full_Package.tar.gz', $lines),
			'the new entry is behind that of the old version');
		$this->assertStringContainsString("#  5.4.9  taken from the GitHub release asset", $checksums);
		$this->assertStringContainsString('downloads.joomla.org/cms/joomla5/5-4-9', $checksums);
		// the notes stay in the comment block, in front of the checksums
		$this->assertLessThan(strpos($checksums, self::Hash8), strpos($checksums, '#  5.4.9'));
	}

	public function testApplyKeepsWhatLintAndInstallerRead()
	{
		list($workflow, $checksums) = apply(self::Workflow, self::Checksums, '6.1.3', '6.1.4', self::Hash9);
		$this->assertSame(array('5.4.8', '6.1.4'), matrixVersions($workflow));
		foreach (explode("\n", rtrim($checksums)) as $line)
		{
			$this->assertTrue($line === '' || $line[0] === '#'
				|| preg_match('/^[0-9a-f]{64}  Joomla_\d+\.\d+\.\d+-Stable-Full_Package\.tar\.gz$/', $line) === 1, $line);
		}
	}

	#[DataProvider('badApplications')]
	public function testApplyRefusesWhatItCannotDoSafely($from, $to, $hash, $checksums = self::Checksums)
	{
		$this->expectException(InvalidArgumentException::class);
		apply(self::Workflow, $checksums, $from, $to, $hash);
	}

	public static function badApplications()
	{
		return array(
			'other line' => array('5.4.8', '5.5.0', self::Hash9),
			'older' => array('6.1.3', '6.1.2', self::Hash9),
			'same' => array('6.1.3', '6.1.3', self::Hash9),
			'not in the matrix' => array('5.4.7', '5.4.9', self::Hash9),
			'garbage version' => array('5.4.8', '5.4.9; rm -rf /', self::Hash9),
			'short hash' => array('5.4.8', '5.4.9', 'abc'),
			'upper case hash' => array('5.4.8', '5.4.9', strtoupper(self::Hash9)),
			'already listed' => array('5.4.8', '5.4.9', self::Hash9,
				self::Checksums.self::Hash9."  Joomla_5.4.9-Stable-Full_Package.tar.gz\n"),
		);
	}
}
