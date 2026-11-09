<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

/**
 * Reverse DNS lookups (PTR records) with a time limit, for the reverse-DNS
 * risk signal (see RiskHelper).
 *
 * PHP's gethostbyaddr() can't be given a timeout, and the reverse zone of an
 * address belongs to whoever owns the address: an attacker can make the
 * lookups of their addresses hang until the system resolver gives up (its
 * timeout times its attempts times the name servers - easily half a minute),
 * which holds a PHP worker for that long with every failed login. So the
 * query is sent here, over UDP, to the name servers of /etc/resolv.conf, and
 * given up on after a fraction of a second.
 */
class DnsHelper
{
	// for all name servers together
	public const TimeoutSeconds = 1.0;

	public const DefaultResolvConf = '/etc/resolv.conf';

	private const TypePtr = 12;
	private const ClassIn = 1;

	/**
	 * The name servers of a resolv.conf file (at most 3, as the C library
	 * uses), in the form stream_socket_client() takes them.
	 *
	 * @return string[] e.g. "udp://192.0.2.53:53", "udp://[2001:db8::53]:53"
	 */
	public static function nameservers($resolvConf = self::DefaultResolvConf)
	{
		$contents = @file_get_contents($resolvConf);
		if (!is_string($contents))
		{
			return array();
		}
		$servers = array();
		foreach (preg_split('/\R/', $contents) as $line)
		{
			if (!preg_match('/^\s*nameserver\s+(\S+)/', $line, $m))
			{
				continue;
			}
			// an IPv6 address may carry a zone ("fe80::1%eth0"), which
			// stream_socket_client() doesn't take
			$address = explode('%', $m[1], 2)[0];
			if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
			{
				$servers[] = 'udp://'.$address.':53';
			}
			elseif (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
			{
				$servers[] = 'udp://['.$address.']:53';
			}
			if (count($servers) === 3)
			{
				break;
			}
		}
		return $servers;
	}

	/**
	 * The name of the PTR record of $ip ("4.3.2.1.in-addr.arpa", or the
	 * nibbles of an IPv6 address under ip6.arpa), null if $ip is no address.
	 */
	public static function ptrName($ip)
	{
		$bin = @inet_pton((string) $ip);
		if ($bin === false)
		{
			return null;
		}
		if (strlen($bin) === 4)
		{
			return implode('.', array_reverse(array_map('ord', str_split($bin)))).'.in-addr.arpa';
		}
		return implode('.', array_reverse(str_split(bin2hex($bin)))).'.ip6.arpa';
	}

	/**
	 * A DNS query (RFC 1035) for the PTR record $name, recursion desired.
	 */
	public static function buildQuery($id, $name)
	{
		$query = pack('nnnnnn', $id & 0xffff, 0x0100, 1, 0, 0, 0);
		foreach (explode('.', $name) as $label)
		{
			$query .= chr(strlen($label)).$label;
		}
		return $query."\0".pack('nn', self::TypePtr, self::ClassIn);
	}

	/**
	 * Reads the (possibly compressed) domain name at $offset of $packet.
	 *
	 * @param int $next set to the offset after the name where it is stored
	 * @return string|null null if the name is malformed
	 */
	private static function readName($packet, $offset, &$next)
	{
		$labels = array();
		$length = 0;
		$jumps = 0;
		$next = null;
		while (true)
		{
			if ($offset >= strlen($packet))
			{
				return null;
			}
			$byte = ord($packet[$offset]);
			if ($byte === 0)
			{
				$next = $next ?? $offset + 1;
				return implode('.', $labels);
			}
			if (($byte & 0xc0) === 0xc0)
			{
				// a pointer to a name elsewhere in the packet
				if ($offset + 1 >= strlen($packet) || ++$jumps > 64)
				{
					return null;
				}
				$next = $next ?? $offset + 2;
				$offset = (($byte & 0x3f) << 8) | ord($packet[$offset + 1]);
				continue;
			}
			if (($byte & 0xc0) !== 0 || $offset + 1 + $byte > strlen($packet))
			{
				return null;
			}
			$labels[] = substr($packet, $offset + 1, $byte);
			$length += $byte + 1;
			if ($length > 255)
			{
				return null;
			}
			$offset += 1 + $byte;
		}
	}

	/**
	 * What the response $packet to the query $id says.
	 *
	 * @return string|null|false the host name of the (first) PTR record; null
	 *                           if there is none (NXDOMAIN, no such record, an
	 *                           error of the server); false if $packet is no
	 *                           (well-formed) response to the query
	 */
	public static function parsePtrResponse($packet, $id)
	{
		$packet = (string) $packet;
		if (strlen($packet) < 12)
		{
			return false;
		}
		$header = unpack('nid/nflags/nqd/nan', substr($packet, 0, 8));
		if ($header['id'] !== ($id & 0xffff) || ($header['flags'] & 0x8000) === 0)
		{
			return false;
		}
		if (($header['flags'] & 0x000f) !== 0)
		{
			return null; // NXDOMAIN, SERVFAIL, ...
		}
		$offset = 12;
		for ($i = 0; $i < $header['qd']; ++$i)
		{
			if (self::readName($packet, $offset, $offset) === null)
			{
				return false;
			}
			$offset += 4;
		}
		for ($i = 0; $i < $header['an']; ++$i)
		{
			if (self::readName($packet, $offset, $offset) === null || $offset + 10 > strlen($packet))
			{
				return false;
			}
			$record = unpack('ntype/nclass/Nttl/nlength', substr($packet, $offset, 10));
			$offset += 10;
			if ($offset + $record['length'] > strlen($packet))
			{
				return false;
			}
			if ($record['type'] === self::TypePtr && $record['class'] === self::ClassIn)
			{
				$host = self::readName($packet, $offset, $ignored);
				return ($host === null || $host === '') ? null : $host;
			}
			// e.g. the CNAME of a classless delegation (RFC 2317)
			$offset += $record['length'];
		}
		return null;
	}

	/**
	 * The host name of the PTR record of $ip.
	 *
	 * @param string[]|null $servers as nameservers() returns them (default)
	 * @return string|null|false the host name; null if there is none or no
	 *                           answer came in time; false if no lookup could
	 *                           be made (no name server known, $ip no address)
	 */
	public static function reverseLookup($ip, $timeout = self::TimeoutSeconds, ?array $servers = null)
	{
		$name = self::ptrName($ip);
		$servers = $servers ?? self::nameservers();
		if ($name === null || count($servers) === 0)
		{
			return false;
		}
		$deadline = microtime(true) + $timeout;
		foreach ($servers as $server)
		{
			$remaining = $deadline - microtime(true);
			if ($remaining <= 0)
			{
				break;
			}
			$socket = @stream_socket_client($server, $errno, $error, $remaining);
			if ($socket === false)
			{
				continue;
			}
			try
			{
				$id = random_int(0, 0xffff);
				if (@fwrite($socket, self::buildQuery($id, $name)) === false)
				{
					continue;
				}
				// the socket is connected: only the server's datagrams arrive
				while (($remaining = $deadline - microtime(true)) > 0)
				{
					$read = array($socket);
					$write = $except = null;
					$seconds = (int) floor($remaining);
					if (@stream_select($read, $write, $except, $seconds, (int) (($remaining - $seconds) * 1000000)) < 1)
					{
						break;
					}
					$packet = @fread($socket, 4096);
					if ($packet === false || $packet === '')
					{
						break; // e.g. the port is unreachable
					}
					$result = self::parsePtrResponse($packet, $id);
					if ($result !== false)
					{
						return $result;
					}
					// not the answer to this query: wait on
				}
			}
			finally
			{
				fclose($socket);
			}
		}
		// no answer in time: as good as no record (and a reverse zone which
		// doesn't answer is no sign of a well-run network either)
		return null;
	}
}
