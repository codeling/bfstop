<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Helper;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Repository\BlockRepository;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Uri\Uri;

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
	 * The query of the link of an unblock email (see TokenHelper::unblockLink()):
	 * the token is the 40 hex digits of TokenHelper::getToken(), and nothing
	 * else may follow - the plugin lets a blocked address reach the unblock
	 * page only without a task, see RequestClassifier::unblockPageToken().
	 */
	public const UnblockQueryPattern = '^option=com_bfstop&view=tokenunblock&token=[0-9a-f]{40}$';

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
		$unblockPage = self::unblockPageCondition();
		$lines = array();
		foreach (array_chunk($addresses, self::AddressesPerCondition) as $chunk)
		{
			$conditions = array();
			foreach ($chunk as $address)
			{
				$conditions[] = "-R '".$address."'";
			}
			$condition = implode(' || ', $conditions);
			$lines[] = '<If "'.($unblockPage === null ? $condition : '('.$condition.') && !'.$unblockPage).'">';
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
	 * The path of the unblock page's requests: index.php of the site - or
	 * null if it holds characters which can't go into the condition as they
	 * are. Without Joomla (a script using this class on its own), the site
	 * is taken to be at the root.
	 */
	public static function unblockPagePath()
	{
		try
		{
			$root = (string) Uri::root(true);
		}
		catch (\Throwable $e)
		{
			$root = '';
		}
		$path = rtrim($root, '/').'/index.php';
		return preg_match('#^/[A-Za-z0-9._~/-]*\z#', $path) === 1 ? $path : null;
	}

	/**
	 * The requests of an unblock email's link to the unblock page, which the
	 * block section lets through. The web server refuses every request of a
	 * blocked address, so the link - which the plugin sends to who blocked
	 * themselves - would otherwise lead nowhere. They only get as far as
	 * Joomla: a blocked address is in the block list of the database as
	 * well, and the plugin lets it reach nothing but the unblock page, and
	 * only with a token for one of its own blocks (Bfstop::enforceBlock()).
	 * The stylesheets and pictures of the page stay out of reach, the
	 * confirmation is posted to the page itself.
	 *
	 * @return string|null null if the page's path can't be put into the condition
	 */
	private static function unblockPageCondition()
	{
		$path = self::unblockPagePath();
		return $path === null ? null
			: "(%{REQUEST_URI} == '".$path."' && %{QUERY_STRING} =~ /".self::UnblockQueryPattern."/)";
	}

	/**
	 * The prefix length of the entry an IPv6 client gets in the file, if it
	 * is tracked by a larger network (see entryFor()).
	 */
	public const ClientPrefixLength = IpHelper::TrustPrefixLength;

	/**
	 * What the file is to hold for a block of $tracked - the key the failed
	 * logins of a client are counted under (see IpHelper::trackedAddress()) -
	 * whose client was at $client: an IPv6 client is counted by its /56 (by
	 * default), because it controls all of it, but many providers give their
	 * customers a /64 or less of a shared /56. Joomla blocks the /56, but the
	 * web server, which turns away whatever the entry covers before Joomla
	 * (and the allow list) get a say, only the client's /64. IPv4 addresses,
	 * networks of /64 or less, and addresses which IpHelper::trackedAddress()
	 * doesn't aggregate stay what they are tracked as; so does $tracked if
	 * the client isn't known or not in it.
	 *
	 * @param string      $tracked the address of the block
	 * @param string|null $client  the client's actual address
	 */
	public static function entryFor($tracked, $client)
	{
		if ($client === null || (IpHelper::prefixLength($tracked) ?? 128) >= self::ClientPrefixLength)
		{
			return $tracked;
		}
		$entry = IpHelper::trackedAddress($client, self::ClientPrefixLength);
		return IpHelper::prefixLength($entry) === self::ClientPrefixLength && strpos($entry, ':') !== false &&
			IpHelper::contains($tracked, $entry) ? $entry : $tracked;
	}

	/**
	 * Whether the entry $entry of the file is one a block of $address put
	 * there: $address itself, or the /64 of a client within it (see
	 * entryFor()).
	 */
	public static function isEntryOf($entry, $address)
	{
		$entry = (string) $entry;
		$address = (string) $address;
		if ($entry === $address)
		{
			return true;
		}
		return strpos($entry, ':') !== false && IpHelper::prefixLength($entry) === self::ClientPrefixLength &&
			(IpHelper::prefixLength($address) ?? 128) < self::ClientPrefixLength && IpHelper::contains($address, $entry);
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
	 * Writes the block section in the form the plugin writes it now, keeping
	 * the blocked addresses, the 403 message and the lines added by hand: a
	 * section of an earlier version (see LegacyLines) grants access, and one
	 * written before the unblock page was let through (or for another path
	 * of the site) keeps those who blocked themselves out of it.
	 *
	 * @return bool whether the section is in the current form (now)
	 */
	public function upgradeFormat()
	{
		return $this->locked(function ()
		{
			$section = $this->parseSection();
			$rendered = self::renderSection($section);
			$current = array_values(array_filter($this->extract(), function ($line)
			{
				return trim($line) !== '';
			}));
			if (!$section['legacy'] && $current === $rendered)
			{
				return true;
			}
			if (!is_null($this->logger))
			{
				$this->logger->log($section['legacy']
					? 'Replacing the block section of an earlier version in '.$this->path.
						' - it let everybody who isn\'t blocked past the other access controls of the directory'
					: 'Writing the block section of '.$this->path.' in its current form',
					$section['legacy'] ? Log::WARNING : Log::INFO);
			}
			return $this->insert($rendered);
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
	public function removeLiftedBlocks(BlockRepository $blocks)
	{
		$lifted = $blocks->addressesWithoutActiveBlock();
		// the /64 of a client in a network whose block is over (see
		// entryFor()) may have another active block, say one made by hand:
		// looked up only if there is such an entry
		$active = function () use ($blocks, $lifted)
		{
			$all = $blocks->allAddresses();
			return $all === null ? null : array_values(array_diff($all, $lifted));
		};
		$removed = $this->removeAddresses($lifted, 'the block is over', $active);
		return $removed === false ? 0 : $removed;
	}

	/**
	 * Takes every address with a block in the database out of the file,
	 * whether the block is still active or not: for a file which doesn't
	 * block any more - another blocking mode or another file was chosen. The
	 * plugin wrote these entries, and nothing would take them out once their
	 * blocks are over: the web server would refuse the addresses for good.
	 * The blocks themselves stay in the database, which Joomla goes by.
	 * Entries without a block in the database - added by hand - are left
	 * alone.
	 *
	 * @return int|false the number of entries removed; false if the block
	 *                   list couldn't be read or the file couldn't be written
	 */
	public function removeDatabaseBlocks(BlockRepository $blocks)
	{
		$addresses = $blocks->allAddresses();
		if ($addresses === null)
		{
			return false;
		}
		return $this->removeAddresses($addresses, 'the file is not what blocks');
	}

	/**
	 * Takes out of the file what nothing else would: with blocking through
	 * it ($blocksThroughFile), the addresses whose blocks are over (see
	 * removeLiftedBlocks()), otherwise every address the plugin has blocked
	 * (see removeDatabaseBlocks()).
	 *
	 * @return int|false the number of entries removed; false on an error
	 */
	public function removeStaleBlocks(BlockRepository $blocks, $blocksThroughFile)
	{
		if (!file_exists($this->path))
		{
			return 0;
		}
		return $blocksThroughFile ? $this->removeLiftedBlocks($blocks) : $this->removeDatabaseBlocks($blocks);
	}

	/**
	 * Takes the entries of $addresses out of the block section (see
	 * isEntryOf(): the addresses, and the /64 of a client within them), in
	 * one change of the file.
	 *
	 * @param string[]      $addresses
	 * @param string        $reason    for the log
	 * @param callable|null $active    gives the addresses which are still
	 *                                 blocked (null if that is unknown), whose
	 *                                 entries stay; only asked if an entry is
	 *                                 a /64 within one of $addresses
	 * @return int|false the number of entries removed; false if the file
	 *                   couldn't be written
	 */
	public function removeAddresses(array $addresses, $reason = '', ?callable $active = null)
	{
		$addresses = array_values(array_unique(array_map('strval', $addresses)));
		if (count($addresses) === 0 || !file_exists($this->path))
		{
			return 0;
		}
		return $this->locked(function () use ($addresses, $reason, $active)
		{
			$section = $this->parseSection();
			$removed = array_values(array_intersect($section['addresses'], $addresses));
			$within = array();
			foreach (array_diff($section['addresses'], $removed) as $entry)
			{
				foreach ($addresses as $address)
				{
					if (self::isEntryOf($entry, $address))
					{
						$within[] = $entry;
						break;
					}
				}
			}
			if (count($within) > 0 && $active !== null)
			{
				$stillBlocked = $active();
				$within = $stillBlocked === null ? array() : array_values(array_filter($within,
					function ($entry) use ($stillBlocked)
					{
						foreach ($stillBlocked as $address)
						{
							if (IpHelper::contains($address, $entry))
							{
								return false;
							}
						}
						return true;
					}));
			}
			$removed = array_merge($removed, $within);
			if (count($removed) === 0)
			{
				return 0;
			}
			$section['addresses'] = array_values(array_diff($section['addresses'], $removed));
			if (!$this->insert(self::renderSection($section)))
			{
				return false;
			}
			if (!is_null($this->logger))
			{
				$this->logger->log('Removed '.implode(', ', $removed).' from '.$this->path.
					($reason !== '' ? ': '.$reason : ''), Log::INFO);
			}
			return count($removed);
		});
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
	 * can be taken the change is done anyway, as before - also if somebody
	 * else still holds it after LockWaitSeconds: waiting on would leave this
	 * request (and all which get an address blocked after it) hanging for as
	 * long as that one does, see LockHelper.
	 */
	private function locked(callable $change)
	{
		$lockFile = self::lockDirectory().'/bfstop-htaccess-'.md5($this->path).'.lock';
		$handle = LockHelper::acquire($lockFile, self::LockWaitSeconds);
		if (!$handle)
		{
			if (!is_null($this->logger))
			{
				$this->logger->log("Could not lock '$lockFile'".
					($handle === null ? ' within '.self::LockWaitSeconds.' seconds' : '').
					", changing .htaccess without it", Log::WARNING);
			}
			return $change();
		}
		try
		{
			return $change();
		}
		finally
		{
			LockHelper::release($handle);
		}
	}

	/**
	 * The directory of the .htaccess file: the configured one, the Joomla
	 * root if none is configured. The one place which knows this default -
	 * but for the installer script (plugin/updatescript.php), which keeps a
	 * copy, as it runs while the classes of the version before may still be
	 * loaded.
	 */
	public static function resolvePath($configured): string
	{
		$configured = (string) $configured;
		return $configured === '' ? JPATH_ROOT : $configured;
	}

	// changing the file takes milliseconds: who holds its lock for this long
	// is not going to let go of it
	public const LockWaitSeconds = 10;

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
