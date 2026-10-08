<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Bfstop\Tests\Support\MmdbBuilder;
use Codeling\Plugin\System\Bfstop\Helper\Geo\Reader;
use Codeling\Plugin\System\Bfstop\Helper\Geo\Reader\InvalidDatabaseException;
use PHPUnit\Framework\TestCase;

/**
 * The vendored MaxMind DB reader (src/Helper/Geo, see tools/vendor-geoip.php)
 * with a real database: whoever updates the reader sees here at once if it
 * stopped working.
 */
class GeoReaderTest extends TestCase
{
	private $file;

	protected function setUp(): void
	{
		$this->file = tempnam(sys_get_temp_dir(), 'bfstop-mmdb');
		file_put_contents($this->file, MmdbBuilder::build(array(
			'203.0.113.0/24' => array('country' => array('iso_code' => 'DE', 'names' => array('en' => 'Germany')),
				'location' => array('latitude' => 5, 'longitude' => 7)),
			'198.51.100.0/25' => array('country' => array('iso_code' => 'AT')),
		)));
	}

	protected function tearDown(): void
	{
		@unlink($this->file);
	}

	public function testFindsTheRecordOfAnAddress()
	{
		$reader = new Reader($this->file);
		$record = $reader->get('203.0.113.77');
		$this->assertSame('DE', $record['country']['iso_code']);
		$this->assertSame('Germany', $record['country']['names']['en']);
		$this->assertSame(5, $record['location']['latitude']);
		$this->assertSame('AT', $reader->get('198.51.100.9')['country']['iso_code']);
		$reader->close();
	}

	public function testAddressesWithoutRecordGiveNull()
	{
		$reader = new Reader($this->file);
		$this->assertNull($reader->get('198.51.100.200'));
		$this->assertNull($reader->get('192.0.2.1'));
		$reader->close();
	}

	public function testReportsTheDatabaseMetadata()
	{
		$reader = new Reader($this->file);
		$this->assertSame('BFStop-Test', $reader->metadata()->databaseType);
		$this->assertSame(4, $reader->metadata()->ipVersion);
		$reader->close();
	}

	public function testRejectsAddressesOfAnotherFamily()
	{
		$reader = new Reader($this->file);
		$this->expectException(\InvalidArgumentException::class);
		$reader->get('2001:db8::1');
	}

	public function testRejectsGarbage()
	{
		file_put_contents($this->file, str_repeat('not a maxmind database', 50));
		$this->expectException(InvalidDatabaseException::class);
		new Reader($this->file);
	}

	public function testRejectsATruncatedDatabase()
	{
		file_put_contents($this->file, substr(file_get_contents($this->file), 0, 40));
		$this->expectException(InvalidDatabaseException::class);
		new Reader($this->file);
	}
}
