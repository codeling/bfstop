<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\Geo\Reader;
use Joomla\CMS\Log\Log;

/**
 * Looks up an IP address in a locally-configured MaxMind .mmdb GeoIP
 * database (issues #76 and #169). Deliberately local-file-only, not a
 * third-party web API call - avoids leaking every failed-login/blocked IP
 * address to an external service, and can't disappear the way freegeoip.net
 * did (see #169). Every lookup fails safe: a missing/invalid/unreadable
 * database file or a lookup error is logged at WARNING and results in null,
 * never an exception escaping to the caller.
 */
class GeoHelper
{
	/**
	 * Cheap, needs only a GeoLite2-Country-tier database. Used by the
	 * risk-scoring geo signal (#76).
	 */
	public static function getCountryCode(LoggerHelper $logger, $dbPath, $ipaddress)
	{
		$record = self::lookup($logger, $dbPath, $ipaddress);
		if ($record === null || !isset($record['country']['iso_code']))
		{
			return null;
		}
		return (string) $record['country']['iso_code'];
	}

	/**
	 * Needs a GeoLite2-City-tier database (region/city/postal/lat-long are
	 * not present in a Country-tier database). Used to restore the "click a
	 * blocked IP" admin info view (#169).
	 */
	public static function getCityDetails(LoggerHelper $logger, $dbPath, $ipaddress)
	{
		$record = self::lookup($logger, $dbPath, $ipaddress);
		if ($record === null)
		{
			return null;
		}
		$details = new \stdClass();
		$details->ip = $ipaddress;
		$details->countryCode = $record['country']['iso_code'] ?? '';
		$details->countryName = $record['country']['names']['en'] ?? '';
		$details->region = $record['subdivisions'][0]['names']['en'] ?? '';
		$details->city = $record['city']['names']['en'] ?? '';
		$details->postalCode = $record['postal']['code'] ?? '';
		$details->latitude = $record['location']['latitude'] ?? '';
		$details->longitude = $record['location']['longitude'] ?? '';
		return $details;
	}

	private static function lookup(LoggerHelper $logger, $dbPath, $ipaddress)
	{
		$dbPath = (string) $dbPath;
		if ($dbPath === '')
		{
			return null;
		}
		if (!is_readable($dbPath))
		{
			$logger->log('GeoHelper: GeoIP database file not readable: '.$dbPath, Log::WARNING);
			return null;
		}
		try
		{
			$reader = new Reader($dbPath);
			try
			{
				$record = $reader->get($ipaddress);
			}
			finally
			{
				$reader->close();
			}
			return is_array($record) ? $record : null;
		}
		catch (\Exception $e)
		{
			$logger->log('GeoHelper: GeoIP lookup failed: '.$e->getMessage(), Log::WARNING);
			return null;
		}
	}
}
