<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Component\Bfstop\Administrator\Helper\VersionHelper;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The check which tells the administrator that the installed component and
 * plugin belong to different releases (DisplayController).
 */
class VersionHelperTest extends TestCase
{
	public function testTheVersionIsTheOneOfTheManifestCache()
	{
		$this->assertSame('2.1.3', VersionHelper::getVersion('{"name":"plg_system_bfstop","version":"2.1.3"}'));
		$this->assertSame('2.1.3-rc1', VersionHelper::getVersion('{"version":"2.1.3-rc1","author":"x"}'));
	}

	public function testAManifestWithoutVersionHasNone()
	{
		$this->assertSame('', VersionHelper::getVersion('{"name":"plg_system_bfstop"}'));
		$this->assertSame('', VersionHelper::getVersion('{}'));
	}

	public function testAnEmptyOrBrokenManifestCacheHasNoVersion()
	{
		// json_decode() gives null or no object for these: property_exists()
		// threw a TypeError, which took down the settings page
		foreach (array('', 'null', 'not json', '[]', '"2.1.3"', '{"version":{"x":1}}') as $cache)
		{
			$this->assertSame('', VersionHelper::getVersion($cache), $cache);
		}
		$this->assertSame('', VersionHelper::getVersion(null));
	}

	public static function sameMajorMinor()
	{
		return array(
			'same release' => array('2.1.3', '2.1.3', true),
			'patch differs' => array('2.1.3', '2.1.9', true),
			'pre-release of the same line' => array('2.1.3-rc1', '2.1.0', true),
			'minor differs' => array('2.1.3', '2.2.3', false),
			'major differs' => array('2.1.3', '3.1.3', false),
			'two parts are enough' => array('2.1', '2.1', true),
			// "2.1" and "2.10" must not be taken for each other
			'minor which starts like the other' => array('2.1.0', '2.10.0', false),
			'major which starts like the other' => array('2.1.0', '12.1.0', false),
			'no version' => array('', '2.1.3', false),
			'one part' => array('2', '2.1.3', false),
			'both without version' => array('', '', false),
		);
	}

	#[DataProvider('sameMajorMinor')]
	public function testOnlyReleasesOfTheSameMajorAndMinorVersionBelongTogether($one, $other, $expected)
	{
		$this->assertSame($expected, VersionHelper::checkSameMajorMinor($one, $other));
		$this->assertSame($expected, VersionHelper::checkSameMajorMinor($other, $one), 'in either order');
	}
}
