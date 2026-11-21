<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Joomla\CMS\Http\HttpFactory;
use Joomla\CMS\Uri\Uri;

/**
 * Checks whether the web server honours the block section of the .htaccess
 * file (issue #285): whether it reads .htaccess files in that directory at
 * all (Apache's AllowOverride), and understands the directives the section
 * is written in (<If> and "Require", Apache 2.4).
 *
 * The block section itself can't be tried: it turns away blocked
 * addresses, and the site has none to send a request from. So the check
 * makes a probe directory in the directory of the .htaccess file, whose own
 * .htaccess has a condition of the same form, and refuses the requests with
 * a query of its choosing (HtaccessHelper::writeProbe()). It requests the
 * probe's file over HTTP - from the site's own address, as a visitor would -
 * once with another query, which has to get the file, and once with that
 * one, which has to be refused. The directory is removed again right away.
 */
final class HtaccessCheckHelper
{
	public const Effective = 'effective';
	// the probe was served all the same
	public const Ignored = 'ignored';
	// the server failed on the probe's .htaccess (500): it doesn't know a directive
	public const Broken = 'broken';
	// the check could not be made; the detail says why
	public const Unknown = 'unknown';

	/**
	 * The URL the directory $dir is served at, if it is the site's
	 * directory or one in it; null otherwise.
	 */
	public static function urlOf(string $dir, string $siteRoot, string $siteUrl): ?string
	{
		$dir = realpath($dir);
		$root = realpath($siteRoot);
		if ($dir === false || $root === false)
		{
			return null;
		}
		if ($dir === $root)
		{
			return rtrim($siteUrl, '/');
		}
		if (strpos($dir, $root.DIRECTORY_SEPARATOR) !== 0)
		{
			return null;
		}
		$relative = str_replace(DIRECTORY_SEPARATOR, '/', substr($dir, strlen($root) + 1));
		return rtrim($siteUrl, '/').'/'.implode('/', array_map('rawurlencode', explode('/', $relative)));
	}

	/**
	 * Runs the check for the .htaccess file in $dir.
	 *
	 * @param callable|null $fetch url => array(status, body), or null if the
	 *                             request failed; null for a real HTTP request
	 * @return array array(result, detail): one of the constants, and what was
	 *               seen (a status, a reason) for the message
	 */
	public static function run(string $dir, ?callable $fetch = null, ?string $siteRoot = null, ?string $siteUrl = null): array
	{
		$url = self::urlOf($dir, $siteRoot ?? JPATH_ROOT, $siteUrl ?? Uri::root());
		if ($url === null)
		{
			return array(self::Unknown, 'outside');
		}
		$token = bin2hex(random_bytes(16));
		$probe = rtrim($dir, '/\\').'/bfstop-check-'.$token;
		if (!HtaccessHelper::writeProbe($probe, $token))
		{
			HtaccessHelper::removeProbe($probe);
			return array(self::Unknown, 'write');
		}
		try
		{
			$fetch ??= array(self::class, 'fetch');
			$file = $url.'/'.basename($probe).'/'.HtaccessHelper::ProbeFile;
			$allowed = $fetch($file.'?allow='.$token);
			if ($allowed === null)
			{
				return array(self::Unknown, 'request');
			}
			if ((int) $allowed[0] === 500)
			{
				return array(self::Broken, '500');
			}
			if ((int) $allowed[0] !== 200 || trim((string) $allowed[1]) !== $token)
			{
				// something else stands between the site and its own files
				// (authentication, a firewall, a CDN): the check can't say
				return array(self::Unknown, (string) (int) $allowed[0]);
			}
			$denied = $fetch($file.'?deny='.$token);
			if ($denied === null)
			{
				return array(self::Unknown, 'request');
			}
			switch ((int) $denied[0])
			{
				case 403:
					return array(self::Effective, '403');
				case 500:
					return array(self::Broken, '500');
				case 200:
					return array(self::Ignored, '200');
				default:
					return array(self::Unknown, (string) (int) $denied[0]);
			}
		}
		finally
		{
			HtaccessHelper::removeProbe($probe);
		}
	}

	/**
	 * A GET request of $url, not to be answered from a cache on the way:
	 * array(status, body), or null if it failed.
	 */
	public static function fetch(string $url): ?array
	{
		try
		{
			$http = HttpFactory::getHttp(array(), array('curl', 'stream'));
			$response = $http->get($url, array('Cache-Control' => 'no-cache', 'Pragma' => 'no-cache'), 10);
			return array((int) $response->getStatusCode(), (string) $response->getBody());
		}
		catch (\Throwable $e)
		{
			return null;
		}
	}
}
