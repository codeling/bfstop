<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;

/**
 .htaccess management class, based on the work by Jan-Paul Kleemans from
	 https://github.com/jpkleemans/Brute-Force-Login-Protection
 (licensed under GNU GENERAL PUBLIC LICENSE v2)
*/
class HtaccessHelper
{
	/**
	 * Path to .htaccess file
	 *
	 * @var string
	 */
	private $path;

	private $logger;

	/**
	 * The block section of earlier versions: a <RequireAll> of "Require all
	 * granted" and one "Require not ip" line per address. Still read (and
	 * replaced by the current form whenever the section is written, see
	 * upgradeFormat()), never written: Apache combines the authorization
	 * directives at the top level of a configuration section with an implicit
	 * <RequireAny>, so the "Require all granted" in it let everybody who isn't
	 * blocked past every other access control of the directory - HTTP
	 * authentication ("Require valid-user"), "Require ip", "Require all denied".
	 */
	public const BlockPrefix = 'Require not ip ';
	private const LegacyLines = array('<RequireAll>', 'Require all granted', '</RequireAll>');

	/**
	 * The block section only denies: an <If> holding "Require all denied" for
	 * requests from a blocked address. A request it doesn't match keeps
	 * whatever authorization the directory has; one it matches is refused,
	 * whatever that is (AuthMerging Off: the <If> replaces it).
	 */
	private const DenyLine = 'Require all denied';
	private const EndIfLine = '</If>';
	private const ErrorDocumentPrefix = 'ErrorDocument 403 ';

	/**
	 * Addresses per <If>: Apache reads configuration lines of up to 8 KB, an
	 * <If> line holds about 50 characters per address.
	 */
	public const AddressesPerCondition = 50;

	/**
	 * The most addresses the block section holds. Apache reads the file again
	 * for every request, and a visitor with many addresses can get many of
	 * them blocked: without a limit, that slows down the whole site. Blocks
	 * beyond it still apply in the database - for requests that get as far as
	 * Joomla.
	 */
	public const MaxBlockLines = 2000;

	/**
	 * Construct class with given $path.
	 *
	 * @param string $dir
	 */
	public function __construct($dir, $logger)
	{
		$this->path = $dir . '/.htaccess';
		$this->logger = $logger;
	}

	public function getFileName()
	{
		return $this->path;
	}

	/**
	 * Check if .htaccess file is found, readable and writeable.
	 *
	 * @return array
	 */
	public function checkRequirements()
	{
		$result = array(
			'apacheserver' =>
				strstr(preg_replace("/[^a-z]+/", "", strtolower($_SERVER['SERVER_SOFTWARE'] ?? '')), 'apache'),
			'found'		=> file_exists($this->path),
			'readable'	=> is_readable($this->path),
			'writeable'	=> is_writeable($this->path)
		);
		return $result;
	}

	/**
	 * What the block section holds: the blocked addresses (in the order they
	 * were added), the ErrorDocument 403 line (or null) and any other lines,
	 * which somebody wrote into it by hand. Read from both the current and
	 * the earlier form (see LegacyLines).
	 *
	 * @return array{addresses: string[], errorDocument: string|null, other: string[], legacy: bool}
	 */
	private function parseSection()
	{
		$section = array('addresses' => array(), 'errorDocument' => null, 'other' => array(), 'legacy' => false);
		foreach ($this->extract() as $line)
		{
			$trimmed = trim($line);
			if ($trimmed === '' || $trimmed === self::DenyLine || $trimmed === self::EndIfLine)
			{
				continue;
			}
			if (in_array($trimmed, self::LegacyLines, true))
			{
				$section['legacy'] = true;
			}
			elseif (strpos($trimmed, self::BlockPrefix) === 0)
			{
				$section['legacy'] = true;
				$section['addresses'][] = substr($trimmed, strlen(self::BlockPrefix));
			}
			elseif (strpos($trimmed, '<If ') === 0)
			{
				preg_match_all("/-R '([^']*)'/", $trimmed, $matches);
				foreach ($matches[1] as $address)
				{
					$section['addresses'][] = $address;
				}
			}
			elseif (strpos($trimmed, self::ErrorDocumentPrefix) === 0)
			{
				$section['errorDocument'] = $trimmed;
			}
			else
			{
				$section['other'][] = $line;
			}
		}
		$section['addresses'] = array_values(array_unique($section['addresses']));
		return $section;
	}

	/**
	 * The lines of the block section for $section (see parseSection()). Only
	 * addresses and networks get into a condition: what is written there is
	 * part of the web server's configuration.
	 *
	 * @return string[]
	 */
	private static function renderSection(array $section)
	{
		$addresses = array_values(array_filter($section['addresses'], array(IpHelper::class, 'isValidIpOrSubnet')));
		$lines = array();
		foreach (array_chunk($addresses, self::AddressesPerCondition) as $chunk)
		{
			$conditions = array();
			foreach ($chunk as $address)
			{
				$conditions[] = "-R '".$address."'";
			}
			$lines[] = '<If "'.implode(' || ', $conditions).'">';
			$lines[] = self::DenyLine;
			$lines[] = self::EndIfLine;
		}
		if ($section['errorDocument'] !== null)
		{
			$lines[] = $section['errorDocument'];
		}
		return array_merge($lines, $section['other']);
	}

	/**
	 * Return array of denied IP addresses from .htaccess.
	 *
	 * @return array
	 */
	public function getDeniedIPs()
	{
		// the list is shown in the backend, and what it holds is whatever
		// somebody wrote into the file: only addresses and subnets are
		// passed on
		return array_values(array_filter($this->parseSection()['addresses'],
			array(IpHelper::class, 'isValidIpOrSubnet')));
	}

	/**
	 * Blocks $IP in .htaccess.
	 *
	 * @param string $IP
	 * @return boolean
	 */
	public function denyIP($IP)
	{
		// the value ends up in a web server configuration file as is: a
		// newline or anything but an address/subnet in it would add
		// arbitrary directives (or make Apache reject the whole file, taking
		// the site down)
		if (!IpHelper::isValidIpOrSubnet($IP))
		{
			if (!is_null($this->logger))
			{
				$this->logger->log("Refusing to write invalid IP address '".
					addcslashes((string) $IP, "\0..\37\177")."' to .htaccess!", Log::ERROR);
			}
			return false;
		}
		return $this->locked(function () use ($IP)
		{
			$section = $this->parseSection();
			if (!in_array($IP, $section['addresses'], true))
			{
				if (count($section['addresses']) >= self::MaxBlockLines)
				{
					if (!is_null($this->logger))
					{
						$this->logger->log("Not adding '$IP' to .htaccess: it holds ".count($section['addresses']).
							" addresses already", Log::ERROR);
					}
					return false;
				}
				$section['addresses'][] = $IP;
			}
			return $this->insert(self::renderSection($section));
		});
	}

	/**
	 * Lifts the block of $IP in .htaccess.
	 *
	 * @param string $IP
	 * @return boolean
	 */
	public function undenyIP($IP)
	{
		return $this->locked(function () use ($IP)
		{
			$section = $this->parseSection();
			$key = array_search((string) $IP, $section['addresses'], true);
			if ($key === false && !$section['legacy'])
			{
				return true;
			}
			if ($key !== false)
			{
				unset($section['addresses'][$key]);
			}
			return $this->insert(self::renderSection($section));
		});
	}

	/**
	 * Whether the file still has a block section of an earlier version, which
	 * grants access (see LegacyLines).
	 */
	public function hasLegacySection()
	{
		return $this->parseSection()['legacy'];
	}

	/**
	 * Replaces a block section of an earlier version (see LegacyLines) by the
	 * current form, keeping the blocked addresses and the 403 message.
	 *
	 * @return bool whether the file has no such section (any more)
	 */
	public function upgradeFormat()
	{
		return $this->locked(function ()
		{
			$section = $this->parseSection();
			if (!$section['legacy'])
			{
				return true;
			}
			if (!is_null($this->logger))
			{
				$this->logger->log('Replacing the block section of an earlier version in '.$this->path.
					' - it let everybody who isn\'t blocked past the other access controls of the directory', Log::WARNING);
			}
			return $this->insert(self::renderSection($section));
		});
	}

	/**
	 * Takes the addresses whose blocks have run out or were lifted out of the
	 * file. The web server knows nothing about durations or unblocks, so the
	 * entry has to be removed, or the block would be permanent (and the file
	 * would grow with every address ever blocked). Entries without a block in
	 * the database - the ones an administrator added to the file by hand -
	 * are left alone. Called by the plugin whenever it blocks and once a day,
	 * and by com_bfstop right after it unblocked something.
	 *
	 * @return int the number of entries removed
	 */
	public function removeLiftedBlocks(DatabaseHelper $db)
	{
		$addresses = $db->getAddressesWithoutActiveBlock();
		if (count($addresses) === 0)
		{
			return 0;
		}
		$present = $this->getDeniedIPs();
		$removed = 0;
		foreach ($addresses as $address)
		{
			if (in_array($address, $present, true))
			{
				if (!is_null($this->logger))
				{
					$this->logger->log('Block of '.$address.' is over, removing it from '.
						$this->getFileName(), Log::INFO);
				}
				if ($this->undenyIP($address))
				{
					++$removed;
				}
			}
		}
		return $removed;
	}

	/**
	 * Edit ErrorDocument 403 line in .htaccess.
	 *
	 * @param string $message
	 * @return boolean
	 */
	public function edit403Message($message)
	{
		if (empty($message))
		{
			return $this->remove403Message();
		}
		// a line break would start a new directive
		if (preg_match('/[\x00-\x1f\x7f]/', $message))
		{
			if (!is_null($this->logger))
			{
				$this->logger->log("Refusing to write a 403 message containing control characters to .htaccess!", Log::ERROR);
			}
			return false;
		}

		$line = self::ErrorDocumentPrefix.'"'.addcslashes($message, '"\\').'"';

		return $this->locked(function () use ($line)
		{
			$section = $this->parseSection();
			$section['errorDocument'] = $line;
			return $this->insert(self::renderSection($section));
		});
	}

	/**
	 * Remove ErrorDocument 403 line from .htaccess.
	 *
	 * @return boolean
	 */
	public function remove403Message()
	{
		return $this->locked(function ()
		{
			$section = $this->parseSection();
			if ($section['errorDocument'] === null && !$section['legacy'])
			{
				return true;
			}
			$section['errorDocument'] = null;
			return $this->insert(self::renderSection($section));
		});
	}

	/**
	 * Runs a read-modify-write cycle of the .htaccess file while holding an
	 * exclusive lock, so that concurrent requests (several clients getting
	 * blocked at once is exactly when this happens) don't overwrite each
	 * other's changes: each of them would otherwise read the file, add its
	 * line and write the result back, losing the lines the others added in
	 * between. The lock is a file in the temporary directory, not the
	 * .htaccess itself, which is replaced as a whole when written. If no lock
	 * can be taken the change is done anyway, as before.
	 */
	private function locked(callable $change)
	{
		$lockFile = self::lockDirectory().'/bfstop-htaccess-'.md5($this->path).'.lock';
		$handle = @fopen($lockFile, 'c');
		if ($handle === false || !flock($handle, LOCK_EX))
		{
			if (!is_null($this->logger))
			{
				$this->logger->log("Could not lock '$lockFile', changing .htaccess without it", Log::WARNING);
			}
			if ($handle !== false)
			{
				fclose($handle);
			}
			return $change();
		}
		try
		{
			return $change();
		}
		finally
		{
			flock($handle, LOCK_UN);
			fclose($handle);
		}
	}

	/**
	 * Where lock files go (also those of the plugin, see Bfstop): Joomla's own
	 * temporary directory if there is one we can use, not the system's: that
	 * one is shared with other users of the machine on many hosts, who could
	 * then hold the lock (or plant a link under its name).
	 */
	public static function lockDirectory()
	{
		try
		{
			$tmp = (string) Factory::getApplication()->get('tmp_path');
			if ($tmp !== '' && is_dir($tmp) && is_writable($tmp))
			{
				return rtrim($tmp, '/\\');
			}
		}
		catch (\Throwable $e)
		{
			// no application (e.g. in a script): use the system's
		}
		return sys_get_temp_dir();
	}

	/**
	 * Replaces the file as a whole: the new content is written next to it and
	 * renamed over it. Writing into the file itself would truncate it first,
	 * and a request served (or a crash) in between would see a part of it - for
	 * a configuration file of the web server, an error page for the whole site.
	 * Falls back to writing into the file if the directory doesn't allow
	 * creating files, which hosts which only make the file itself writable need.
	 */
	private function write($content)
	{
		$target = is_link($this->path) ? (realpath($this->path) ?: $this->path) : $this->path;
		$temporary = $target.'.bfstop-'.bin2hex(random_bytes(6));
		if (@file_put_contents($temporary, $content) === strlen($content))
		{
			@chmod($temporary, file_exists($target) ? (fileperms($target) & 0777) : 0644);
			if (@rename($temporary, $target))
			{
				return true;
			}
		}
		@unlink($temporary);
		return file_put_contents($target, $content, LOCK_EX) !== false;
	}

	private static $marker = 'BFStop Blocks';

	/**
	 * Return array of strings from between BEGIN and END markers from .htaccess.
	 *
	 * @return array Array of strings from between BEGIN and END markers from .htaccess.
	 */
	private function extract()
	{
		$result = array();

		if (!file_exists($this->path))
		{
			return $result;
		}

		if ($markerdata = explode("\n", implode('', file($this->path))))
		{
			$state = false;
			foreach ($markerdata as $markerline)
			{
				if (strpos($markerline, '# END ' . self::$marker) !== false)
				{
					$state = false;
				}
				if ($state)
				{
					// a file saved with Windows line ends (e.g. uploaded by FTP
					// in ASCII mode) has a \r at the end of every line
					$result[] = rtrim($markerline, "\r");
				}
				if (strpos($markerline, '# BEGIN ' . self::$marker) !== false)
				{
					$state = true;
				}
			}
		}

		return $result;
	}

	/**
	 * Insert an array of strings into .htaccess, placing it between BEGIN and END markers.
	 * Replace existing marked info. Retain surrounding data.
	 * Create file if none exists.
	 *
	 * @param string $insertion
	 * @return bool True on write success, false on failure.
	 */
	private function insert($insertion)
	{
		if (!file_exists($this->path) || is_writeable($this->path))
		{
			if (!file_exists($this->path))
			{
				$markerdata = '';
			}
			else
			{
				$markerdata = explode("\n", implode('', file($this->path)));
			}

			$newContent = '';

			$foundit = false;
			if ($markerdata)
			{
				$lineCount = count($markerdata);

				$state = true;
				foreach ($markerdata as $n => $markerline)
				{
					if (strpos($markerline, '# BEGIN ' . self::$marker) !== false)
					{
						$state = false;
					}

					if ($state)
					{ // Non-BFLP lines
						if ($n + 1 < $lineCount)
						{
							$newContent .= "{$markerline}\n";
						}
						else
						{
							$newContent .= "{$markerline}";
						}
					}

					if (strpos($markerline, '# END ' . self::$marker) !== false)
					{
						$newContent .= "# BEGIN ".self::$marker."\n";
						if (is_array($insertion))
						{
							foreach ($insertion as $insertline)
							{
								$newContent .= "{$insertline}\n";
							}
						}
						$newContent .= "# END ".self::$marker."\n";

						$state = true;
						$foundit = true;
					}
				}

				// If BEGIN marker found but missing END marker
				if ($state === false)
				{
					if (!is_null($this->logger))
					{
						$this->logger->log("corrupted .htaccess: BEGIN marker was found, but not END!", Log::ERROR);
					}
					return false;
				}
			}

			if (!$foundit)
			{
				// insert at the very beginning:
				$beginContent = "# BEGIN ".self::$marker."\n";
				foreach ($insertion as $insertline)
				{
					$beginContent .= "{$insertline}\n";
				}
				$beginContent .= "# END ".self::$marker."\n\n";
				$newContent = $beginContent . $newContent;
			}

			return $this->write($newContent);
		}
		if (!is_null($this->logger))
		{
			$this->logger->log(".htaccess file is not writable!", Log::ERROR);
		}
		return false;
	}
}
