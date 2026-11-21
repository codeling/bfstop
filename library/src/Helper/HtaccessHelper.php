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
	// the start of an <If> section (not of <IfModule>, <IfDefine>, ...)
	private const IfStart = '/^<If[\s>]/i';

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

	// the file a probe directory holds besides its .htaccess (see writeProbe())
	public const ProbeFile = 'probe.html';
	// the address of the probe's condition: TEST-NET-1, never a real client
	private const ProbeAddress = '192.0.2.1';

	/**
	 * The .htaccess of a probe: an <If> with "Require all denied" as the
	 * block section has, for an address no client has - or the query
	 * "deny=$token". Whether the web server honours the block section is
	 * then a matter of whether a request of the probe with that query is
	 * refused, and one with another query is not (see writeProbe()).
	 *
	 * @param string $token hex digits
	 * @return string[]
	 */
	public static function probeLines(string $token): array
	{
		if (!preg_match('/^[0-9a-f]{16,64}$/', $token))
		{
			throw new \InvalidArgumentException('The token of a probe is 16 to 64 hex digits');
		}
		return array(
			'<If "-R \''.self::ProbeAddress.'\' || %{QUERY_STRING} == \'deny='.$token.'\'">',
			self::DenyLine,
			self::EndIfLine,
		);
	}

	/**
	 * Makes the probe directory $dir (which must not exist): a .htaccess (see
	 * probeLines()) and a file with $token as its content.
	 */
	public static function writeProbe(string $dir, string $token): bool
	{
		$lines = self::probeLines($token);
		if (file_exists($dir) || !@mkdir($dir, 0755))
		{
			return false;
		}
		return @file_put_contents($dir.'/.htaccess', implode("\n", $lines)."\n") !== false &&
			@file_put_contents($dir.'/'.self::ProbeFile, $token) !== false;
	}

	/**
	 * Removes a probe directory made by writeProbe(), and only that: its two
	 * files, then the directory.
	 */
	public static function removeProbe(string $dir): void
	{
		@unlink($dir.'/.htaccess');
		@unlink($dir.'/'.self::ProbeFile);
		@rmdir($dir);
	}

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

	public const ServerApache = 'apache';
	public const ServerLiteSpeed = 'litespeed';
	public const ServerNginx = 'nginx';
	public const ServerOther = 'other';

	/**
	 * Which web server the SERVER_SOFTWARE $serverSoftware names, as far as
	 * the .htaccess file goes: Apache reads it; nginx never does (the blocks
	 * in it do nothing); LiteSpeed reads it, but not every directive of
	 * Apache - whether it honours the <If> sections the blocks are written
	 * in depends on its edition and version. Anything else (or a server
	 * which doesn't say) is "other".
	 */
	public static function webServer($serverSoftware): string
	{
		$software = strtolower((string) $serverSoftware);
		foreach (array(self::ServerLiteSpeed, self::ServerNginx, self::ServerApache) as $server)
		{
			if (str_contains($software, $server))
			{
				return $server;
			}
		}
		return self::ServerOther;
	}

	/**
	 * Check if .htaccess file is found, readable and writeable, and which web
	 * server the site runs on (see webServer()).
	 *
	 * @return array
	 */
	public function checkRequirements()
	{
		$server = self::webServer($_SERVER['SERVER_SOFTWARE'] ?? '');
		$result = array(
			'server'       => $server,
			'apacheserver' => $server === self::ServerApache,
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
	 * Only the blocks the plugin writes count as its own: an <If> whose
	 * condition is nothing but addresses (and, since the unblock page is let
	 * through, the condition of that page - see renderSection()), followed by
	 * "Require all denied" and "</If>". Any other <If> was written by hand
	 * and is kept as it is, with all of its lines up to its own </If>.
	 *
	 * @param string[] $lines the lines of the section (see load())
	 * @return array{addresses: string[], errorDocument: string|null, other: string[], legacy: bool}
	 */
	private static function parseSection(array $lines)
	{
		$section = array('addresses' => array(), 'errorDocument' => null, 'other' => array(), 'legacy' => false);
		$lines = array_values($lines);
		$count = count($lines);
		for ($i = 0; $i < $count; ++$i)
		{
			$line = $lines[$i];
			$trimmed = trim($line);
			if ($trimmed === '')
			{
				continue;
			}
			$addresses = self::blockConditionAddresses($trimmed);
			if ($addresses !== null &&
				trim($lines[$i + 1] ?? '') === self::DenyLine && trim($lines[$i + 2] ?? '') === self::EndIfLine)
			{
				foreach ($addresses as $address)
				{
					$section['addresses'][] = $address;
				}
				$i += 2;
			}
			elseif (preg_match(self::IfStart, $trimmed))
			{
				// written by hand: kept, up to the </If> which closes it
				$depth = 0;
				for (; $i < $count; ++$i)
				{
					$inner = trim($lines[$i]);
					$depth += (preg_match(self::IfStart, $inner) ? 1 : 0) - (strcasecmp($inner, self::EndIfLine) === 0 ? 1 : 0);
					$section['other'][] = $lines[$i];
					if ($depth <= 0)
					{
						break;
					}
				}
			}
			elseif (in_array($trimmed, self::LegacyLines, true))
			{
				$section['legacy'] = true;
			}
			elseif (strpos($trimmed, self::BlockPrefix) === 0)
			{
				$section['legacy'] = true;
				$section['addresses'][] = substr($trimmed, strlen(self::BlockPrefix));
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
	 * The addresses of the condition of an <If> line the plugin writes (see
	 * renderSection()) - "-R 'address'" terms joined by "||", in parentheses
	 * and followed by the exception of the unblock page if it has one - or
	 * null if $line is no such line.
	 *
	 * @return string[]|null
	 */
	private static function blockConditionAddresses($line)
	{
		$terms = "-R '[^']*'(?: \\|\\| -R '[^']*')*";
		$unblockPage = " && !\\(%\\{REQUEST_URI\\} == '[^']*' && %\\{QUERY_STRING\\} =~ /[^/]*/\\)";
		if (!preg_match('#^<If "(?:'.$terms.'|\\('.$terms.'\\)'.$unblockPage.')">$#', $line))
		{
			return null;
		}
		preg_match_all("/-R '([^']*)'/", $line, $matches);
		return $matches[1];
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
	 * entryFor()). An IPv4-mapped entry is the IPv4 address: earlier
	 * versions wrote the address of an IPv4 client in the form the web
	 * server reported it, the block list has it as IPv4 now (see
	 * IpHelper::unmapped()).
	 */
	public static function isEntryOf($entry, $address)
	{
		$entry = IpHelper::unmapped((string) $entry);
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
		return array_values(array_filter(self::parseSection($this->load()['section'])['addresses'],
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
			$file = $this->load();
			$section = self::parseSection($file['section']);
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
			return $this->store($file, self::renderSection($section));
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
			$file = $this->load();
			$section = self::parseSection($file['section']);
			$key = array_search((string) $IP, $section['addresses'], true);
			if ($key === false && !$section['legacy'])
			{
				return true;
			}
			if ($key !== false)
			{
				unset($section['addresses'][$key]);
			}
			return $this->store($file, self::renderSection($section));
		});
	}

	/**
	 * Whether the file still has a block section of an earlier version, which
	 * grants access (see LegacyLines).
	 */
	public function hasLegacySection()
	{
		return self::parseSection($this->load()['section'])['legacy'];
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
			$file = $this->load();
			$section = self::parseSection($file['section']);
			$rendered = self::renderSection($section);
			$current = array_values(array_filter($file['section'], function ($line)
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
			return $this->store($file, $rendered);
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
			$file = $this->load();
			$section = self::parseSection($file['section']);
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
			if (!$this->store($file, self::renderSection($section)))
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
		// by the file, not the site: sites which share a file share its lock
		$lockFile = LockHelper::directory().'/bfstop-htaccess-'.md5($this->path).'.lock';
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
	 * The file as the parts the plugin cares about, read once:
	 *
	 * - before: the lines up to the block section (all the lines if there is
	 *   none)
	 * - section: the lines between the BEGIN and END markers, without the
	 *   markers. If the file has several sections (it is not meant to), their
	 *   lines together
	 * - after: the lines after the first section, those between and after
	 *   the others included
	 * - found: whether there is a section
	 * - unterminated: whether a BEGIN marker has no END marker, which makes
	 *   the file's structure unclear: store() doesn't write it then
	 *
	 * The lines are those of the file split at "\n", so a file which ends
	 * with a line break ends with an empty line; store() relies on that to
	 * write the file back as it was.
	 *
	 * @return array{before: string[], section: string[], after: string[], found: bool, unterminated: bool}
	 */
	private function load()
	{
		$file = array('before' => array(), 'section' => array(), 'after' => array(),
			'found' => false, 'unterminated' => false);
		if (!file_exists($this->path))
		{
			return $file;
		}
		$inside = false;
		foreach (explode("\n", implode('', file($this->path))) as $line)
		{
			if ($inside)
			{
				if (strpos($line, '# END '.self::$marker) !== false)
				{
					$inside = false;
				}
				else
				{
					// a file saved with Windows line ends (e.g. uploaded by FTP
					// in ASCII mode) has a \r at the end of every line
					$file['section'][] = rtrim($line, "\r");
				}
			}
			elseif (strpos($line, '# BEGIN '.self::$marker) !== false)
			{
				$inside = true;
				$file['found'] = true;
			}
			else
			{
				$file[$file['found'] ? 'after' : 'before'][] = $line;
			}
		}
		$file['unterminated'] = $inside;
		return $file;
	}

	/**
	 * Writes $file (see load()) back with $lines as the block section: where
	 * the section was, or - if there was none - at the very beginning of the
	 * file, followed by an empty line. Creates the file if there is none.
	 *
	 * @param string[] $lines
	 * @return bool True on write success, false on failure.
	 */
	private function store(array $file, array $lines)
	{
		if (file_exists($this->path) && !is_writeable($this->path))
		{
			if (!is_null($this->logger))
			{
				$this->logger->log(".htaccess file is not writable!", Log::ERROR);
			}
			return false;
		}
		if ($file['unterminated'])
		{
			if (!is_null($this->logger))
			{
				$this->logger->log("corrupted .htaccess: BEGIN marker was found, but not END!", Log::ERROR);
			}
			return false;
		}
		$section = array_merge(array('# BEGIN '.self::$marker), $lines, array('# END '.self::$marker));
		if (!$file['found'])
		{
			return $this->write(implode("\n", $section)."\n\n".implode("\n", $file['before']));
		}
		$after = $file['after'];
		if (count($after) === 0)
		{
			// the END marker was the last line, without a line break after it
			$after[] = '';
		}
		return $this->write(implode("\n", array_merge($file['before'], $section, $after)));
	}
}
