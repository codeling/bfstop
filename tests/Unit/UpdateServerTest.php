<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use DOMDocument;
use DOMXPath;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

require_once dirname(__DIR__, 2).'/package/update-server.php';

/**
 * package/update-server.php writes the update server's files from the GitHub
 * releases: only published releases which are not test releases, the newest
 * of each version line, for the Joomla! versions of that line.
 */
class UpdateServerTest extends TestCase
{
	private const Hash = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

	private static function release($tag, $options = array())
	{
		$name = "pkg_bfstop-$tag.zip";
		$asset = array('name' => $name,
			'browser_download_url' => "https://github.com/codeling/bfstop/releases/download/$tag/$name");
		if (!array_key_exists('digest', $options) || $options['digest'] !== null)
		{
			$asset['digest'] = $options['digest'] ?? 'sha256:'.self::Hash;
		}
		return array(
			'tag_name' => $tag,
			'html_url' => "https://github.com/codeling/bfstop/releases/tag/$tag",
			'draft' => $options['draft'] ?? false,
			'prerelease' => $options['prerelease'] ?? false,
			'assets' => $options['assets'] ?? array(
				array('name' => "lib_bfstop-$tag.zip", 'browser_download_url' => 'https://example.org/lib'),
				$asset),
		);
	}

	private static function noFetch()
	{
		return function ($url)
		{
			self::fail("Nothing should have been downloaded: $url");
		};
	}

	private static function xpath($xml)
	{
		$doc = new DOMDocument();
		self::assertTrue($doc->loadXML($xml), 'well-formed');
		return new DOMXPath($doc);
	}

	public function testOnlyPublishedStableReleasesAreOffered()
	{
		$stable = updateServerStableReleases(array(
			self::release('2.0.0-rc1', array('prerelease' => true)),
			self::release('2.0.0', array('draft' => true)),
			self::release('1.5.2'),
			self::release('1.5.10'),
			self::release('1.5.9'),
			self::release('2.0.0-rc2'), // a test release which isn't marked as one
		));
		$this->assertSame(array('1.5.10', '1.5.9', '1.5.2'), array_column($stable, 'version'));
	}

	public function testPagesOfReleasesAreFlattened()
	{
		$stable = updateServerStableReleases(array(
			array(self::release('1.5.2'), self::release('1.5.1')),
			array(),
			array(self::release('2.0.0')),
		));
		$this->assertSame(array('2.0.0', '1.5.2', '1.5.1'), array_column($stable, 'version'));
	}

	public function testTheNewestReleaseOfEachLineIsOffered()
	{
		$files = updateServerFiles(array(
			self::release('2.0.0'), self::release('1.5.2'), self::release('2.0.1'), self::release('1.5.1'),
			self::release('2.1.0-beta1', array('prerelease' => true)),
		), self::noFetch());
		$xpath = self::xpath($files['update-pkg.xml']);
		$this->assertSame(array('2.0.1', '1.5.2'), self::values($xpath, '//update/version'));
		$this->assertSame(array('pkg_bfstop', 'pkg_bfstop'), self::values($xpath, '//update/element'));
		$this->assertSame(array('package', 'package'), self::values($xpath, '//update/type'));
		$this->assertSame(array('stable', 'stable'), self::values($xpath, '//update/tags/tag'));
		$this->assertSame(array(
			'https://github.com/codeling/bfstop/releases/download/2.0.1/pkg_bfstop-2.0.1.zip',
			'https://github.com/codeling/bfstop/releases/download/1.5.2/pkg_bfstop-1.5.2.zip'),
			self::values($xpath, '//update/downloads/downloadurl'));
		$this->assertSame(array(self::Hash, self::Hash), self::values($xpath, '//update/sha256'));
		$this->assertSame(array('https://github.com/codeling/bfstop/releases/tag/2.0.1',
			'https://github.com/codeling/bfstop/releases/tag/1.5.2'), self::values($xpath, '//update/infourl'));
		// the php minimum is the one of 2.x; 1.x states none
		$this->assertSame(array('8.2'), self::values($xpath, '//update/php_minimum'));
	}

	public function testTheCollectionPointsAtTheDetailsAndNamesTheNewestVersion()
	{
		$files = updateServerFiles(array(self::release('1.5.2'), self::release('2.0.0')), self::noFetch());
		$xpath = self::xpath($files['update.xml']);
		$this->assertSame(array('https://bfstop.de/update-pkg.xml'),
			self::values($xpath, '//extensionset/extension/@detailsurl'));
		$this->assertSame(array('2.0.0'), self::values($xpath, '//extensionset/extension/@version'));
		$this->assertSame(array('pkg_bfstop'), self::values($xpath, '//extensionset/extension/@element'));
		$this->assertSame(array('package'), self::values($xpath, '//extensionset/extension/@type'));
	}

	public function testBeforeTheFirstTwoRelease()
	{
		$files = updateServerFiles(array(
			self::release('1.5.2'), self::release('2.0.0-rc1', array('prerelease' => true))), self::noFetch());
		$xpath = self::xpath($files['update-pkg.xml']);
		$this->assertSame(array('1.5.2'), self::values($xpath, '//update/version'));
		$this->assertSame(array('1.5.2'), self::values(self::xpath($files['update.xml']), '//extension/@version'));
	}

	public function testAssetWithoutDigestIsHashedFromItsDownload()
	{
		$fetched = array();
		$files = updateServerFiles(array(self::release('1.5.2', array('digest' => null))), function ($url) use (&$fetched)
		{
			$fetched[] = $url;
			return 'the package';
		});
		$this->assertSame(array('https://github.com/codeling/bfstop/releases/download/1.5.2/pkg_bfstop-1.5.2.zip'), $fetched);
		$this->assertSame(array(hash('sha256', 'the package')),
			self::values(self::xpath($files['update-pkg.xml']), '//update/sha256'));
	}

	public function testFailedDownloadIsAnError()
	{
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('Could not download');
		updateServerFiles(array(self::release('1.5.2', array('digest' => null))), fn ($url) => false);
	}

	public function testReleaseWithoutPackageIsAnError()
	{
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('has no asset pkg_bfstop-2.0.0.zip');
		updateServerFiles(array(self::release('2.0.0', array('assets' => array()))), self::noFetch());
	}

	public function testNothingToOfferIsAnError()
	{
		$this->expectException(RuntimeException::class);
		updateServerFiles(array(self::release('2.0.0-rc1', array('prerelease' => true)),
			self::release('2.0.0', array('draft' => true))), self::noFetch());
	}

	public function testReleasesOlderThanTheFirstLineAreNotOffered()
	{
		$files = updateServerFiles(array(self::release('0.9.11'), self::release('0.9.2', array('assets' => array())),
			self::release('1.5.2')), self::noFetch());
		$this->assertSame(array('1.5.2'), self::values(self::xpath($files['update-pkg.xml']), '//update/version'));
		$this->assertSame(array('1.5.2'), self::values(self::xpath($files['update.xml']), '//extension/@version'));
	}

	public function testOnlyReleasesOlderThanTheFirstLineIsNothingToOffer()
	{
		$this->expectException(RuntimeException::class);
		updateServerFiles(array(self::release('0.9.11')), self::noFetch());
	}

	public function testMajorVersionWithoutLineIsAnError()
	{
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('3.0.0 has no version line');
		updateServerFiles(array(self::release('3.0.0'), self::release('2.0.0')), self::noFetch());
	}

	public function testXmlIsEscaped()
	{
		$release = self::release('2.0.0');
		$release['html_url'] = 'https://github.com/codeling/bfstop/releases/tag/2.0.0?a=1&b=<2>';
		$xpath = self::xpath(updateServerFiles(array($release), self::noFetch())['update-pkg.xml']);
		$this->assertSame(array('https://github.com/codeling/bfstop/releases/tag/2.0.0?a=1&b=<2>'),
			self::values($xpath, '//update/infourl'));
	}

	/**
	 * Joomla! matches the targetplatform against the start of its version
	 * (preg_match('/^'.$version.'/', JVERSION)).
	 */
	#[DataProvider('joomlaVersions')]
	public function testTargetPlatformsMatchTheJoomlaVersionsOfTheLine($joomla, $line)
	{
		$matching = array();
		foreach (updateServerLines() as $major => $definition)
		{
			if (preg_match('/^'.$definition['targetplatform'].'/', $joomla))
			{
				$matching[] = $major;
			}
		}
		$this->assertSame($line === null ? array() : array($line), $matching);
	}

	public static function joomlaVersions()
	{
		return array(
			'Joomla 3.10' => array('3.10.12', null),
			'Joomla 4.0' => array('4.0.0', 1),
			'Joomla 4.4' => array('4.4.13', 1),
			'Joomla 5.0' => array('5.0.0', 1),
			'Joomla 5.3' => array('5.3.4', 1),
			'Joomla 5.4' => array('5.4.0', 2),
			'Joomla 5.4 patch' => array('5.4.8', 2),
			'Joomla 6.0' => array('6.0.1', 2),
			'Joomla 6.1' => array('6.1.3', 2),
			'Joomla 7' => array('7.0.0', null),
		);
	}

	private static function values(DOMXPath $xpath, $query)
	{
		$values = array();
		foreach ($xpath->query($query) as $node)
		{
			$values[] = $node->nodeValue;
		}
		return $values;
	}
}
