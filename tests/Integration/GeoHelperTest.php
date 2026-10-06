<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Helper\GeoHelper;
use Joomla\CMS\Log\Log;

class GeoHelperTest extends IntegrationTestCase
{
	public function testEmptyDbPathReturnsNullSilently()
	{
		$logger = $this->logger;
		$this->assertNull(GeoHelper::getCountryCode($logger, '', '203.0.113.5'));
		$this->assertNull(GeoHelper::getCityDetails($logger, '', '203.0.113.5'));
		$this->assertCount(0, $logger->messages);
	}

	public function testUnreadableDbPathReturnsNullWithWarning()
	{
		$logger = $this->logger;
		$this->assertNull(GeoHelper::getCountryCode($logger, '/nonexistent/GeoLite2-Country.mmdb', '203.0.113.5'));
		$this->assertTrue($logger->hasMessage(Log::WARNING, 'not readable'));
	}

	public function testCorruptDbReturnsNullWithWarning()
	{
		$file = tempnam(sys_get_temp_dir(), 'bfstop-geo');
		file_put_contents($file, str_repeat('not a maxmind database', 100));
		try
		{
			$logger = $this->logger;
			$this->assertNull(GeoHelper::getCountryCode($logger, $file, '203.0.113.5'));
			$this->assertTrue($logger->hasMessage(Log::WARNING, 'lookup failed'));
		}
		finally
		{
			unlink($file);
		}
	}

	public function testStreamWrapperPathsAreRefused()
	{
		foreach (array('phar:///tmp/x.phar/GeoLite2.mmdb', 'file:///etc/GeoLite2.mmdb', 'ftp://example.org/GeoLite2.mmdb') as $path)
		{
			$this->assertNull(GeoHelper::getCountryCode($this->logger, $path, '203.0.113.5'));
		}
		$this->assertTrue($this->logger->hasMessage(Log::WARNING, 'not a plain file name'));
	}
}
