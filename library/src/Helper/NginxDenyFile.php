<?php
/*
 * @package BFStop Library (lib_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Helper;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Log\Log;
use Joomla\Registry\Registry;

/**
 * A file of "deny" lines for nginx (issue #285), the counterpart of the
 * block section of .htaccess for sites behind nginx, which never reads
 * .htaccess files: with the setting "nginxDenyFile" and the blocking mode
 * "Full Site", it holds the addresses and networks of the active blocks,
 *
 *   # BFStop blocks: written by Brute Force Stop, do not edit
 *   deny 203.0.113.5;
 *   deny 2001:db8:1:200::/56;
 *
 * for the site's nginx configuration to include (in its server block, before
 * the locations). nginx reads its configuration only when it starts or is
 * reloaded: a change of the file takes effect with the next reload, which
 * whoever runs the server has to arrange (e.g. a systemd path unit or a cron
 * job running "nginx -t && nginx -s reload").
 *
 * The file is always written as a whole, from the block list - so blocks
 * which ran out or were lifted leave it the next time it is written: on the
 * next block, an unblock, and by the daily maintenance. As with .htaccess,
 * entries which would turn away addresses of the allow list or a trusted
 * proxy are left out (blocked in the database only).
 *
 * Only a file this class wrote is ever overwritten - one which begins with
 * its header line - and only a file named *.conf: the path is a setting,
 * and a wrong one must not destroy another file.
 */
final class NginxDenyFile
{
	public const Header = '# BFStop blocks: written by Brute Force Stop, do not edit';
	public const Suffix = '.conf';

	private string $file;
	private ?LoggerHelper $logger;

	public function __construct(string $file, ?LoggerHelper $logger = null)
	{
		$this->file = $file;
		$this->logger = $logger;
	}

	public function getFileName(): string
	{
		return $this->file;
	}

	/**
	 * The file of the settings $params, or null if there is none (the
	 * setting is empty).
	 */
	public static function forSettings(Registry $params, ?LoggerHelper $logger = null): ?self
	{
		$file = trim(Settings::string($params, 'nginxDenyFile'));
		return $file === '' ? null : new self($file, $logger);
	}

	/**
	 * Why the file $file can't be written by this class: 'path' (not an
	 * absolute plain path ending in .conf), 'directory' (its directory doesn't
	 * exist or isn't writable), 'foreign' (it exists, but wasn't written by
	 * this class) - or null if it can.
	 */
	public static function problem(string $file): ?string
	{
		if (preg_match('/[\x00-\x1f]/', $file) || preg_match('#^[a-z][a-z0-9+.-]*://#i', $file) ||
			!(str_starts_with($file, '/') || preg_match('#^[A-Za-z]:[\\\\/]#', $file)) ||
			!str_ends_with(strtolower($file), self::Suffix) || basename($file) === self::Suffix)
		{
			return 'path';
		}
		$dir = dirname($file);
		if (!is_dir($dir) || !is_writable($dir))
		{
			return 'directory';
		}
		if (file_exists($file) && !self::isOwn($file))
		{
			return 'foreign';
		}
		return null;
	}

	private static function isOwn(string $file): bool
	{
		$handle = @fopen($file, 'r');
		if ($handle === false)
		{
			return false;
		}
		$first = fgets($handle);
		fclose($handle);
		return $first !== false && rtrim($first, "\r\n") === self::Header;
	}

	/**
	 * The content of the file for the entries $entries; only addresses and
	 * networks get in (what is written there is part of the server's
	 * configuration), each once, and at most HtaccessHelper::MaxBlockLines.
	 *
	 * @param string[] $entries
	 */
	public static function content(array $entries): string
	{
		$entries = array_slice(array_values(array_unique(array_filter(array_map('strval', $entries),
			array(IpHelper::class, 'isValidIpOrSubnet')))), 0, HtaccessHelper::MaxBlockLines);
		$lines = array(self::Header);
		foreach ($entries as $entry)
		{
			$lines[] = 'deny '.$entry.';';
		}
		return implode("\n", $lines)."\n";
	}

	/**
	 * Writes the file with the entries $entries, in one step (a file next to
	 * it, renamed), unless it holds them already.
	 *
	 * @param string[] $entries
	 */
	public function write(array $entries): bool
	{
		$problem = self::problem($this->file);
		if ($problem !== null)
		{
			$this->log('Not writing the nginx deny file '.$this->file.': '.array(
				'path' => 'it must be an absolute path of a file named *.conf',
				'directory' => 'its directory does not exist or is not writable',
				'foreign' => 'the file exists, but was not written by BFStop',
			)[$problem], Log::ERROR);
			return false;
		}
		$content = self::content($entries);
		if (is_file($this->file) && @file_get_contents($this->file) === $content)
		{
			return true;
		}
		$temporary = $this->file.'.'.bin2hex(random_bytes(4)).'.tmp';
		if (@file_put_contents($temporary, $content) === false || !@rename($temporary, $this->file))
		{
			@unlink($temporary);
			$this->log('Could not write the nginx deny file '.$this->file, Log::ERROR);
			return false;
		}
		@chmod($this->file, 0644);
		return true;
	}

	/**
	 * Writes the file from the block list: the entries of the active blocks
	 * if $blocking (the blocking mode is "Full Site"), else none. Not if the
	 * block list can't be read: the file stays as it is then.
	 */
	public function sync(Repositories $repositories, bool $blocking): bool
	{
		if (!$blocking)
		{
			// nothing is to be blocked by nginx; a file which isn't there yet
			// needn't be made for that
			return !file_exists($this->file) || $this->write(array());
		}
		$addresses = $repositories->blocks()->activeAddresses();
		if ($addresses === null)
		{
			return false;
		}
		$proxies = IpHelper::trustedProxies();
		$entries = array();
		foreach ($addresses as $address)
		{
			$allowed = $repositories->allowList()->entriesOverlapping($address);
			if ($allowed === null)
			{
				// can't tell which addresses would be turned away with it
				return false;
			}
			if (count($allowed) === 0 && !IpHelper::overlapsTrustedProxy($address, $proxies))
			{
				$entries[] = $address;
			}
		}
		return $this->write($entries);
	}

	/**
	 * Writes the file of the settings $params from the block list (see
	 * sync()), if they name one.
	 */
	public static function syncForSettings(Registry $params, Repositories $repositories): ?bool
	{
		$file = self::forSettings($params, $repositories->logger());
		return $file?->sync($repositories, Settings::string($params, 'blockMode') === 'full');
	}

	private function log(string $message, int $priority): void
	{
		$this->logger?->log($message, $priority);
	}
}
