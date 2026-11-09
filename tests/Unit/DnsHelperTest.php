<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Plugin\System\Bfstop\Helper\DnsHelper;
use PHPUnit\Framework\TestCase;

/**
 * The reverse lookup with a time limit used by the reverse-DNS risk signal:
 * what it asks, how it reads the answer (which comes from a name server the
 * owner of the address chose), and that it gives up in time.
 */
class DnsHelperTest extends TestCase
{
	private const Name = '5.113.0.203.in-addr.arpa';

	private static function encodeName($name)
	{
		$encoded = '';
		foreach (explode('.', $name) as $label)
		{
			$encoded .= chr(strlen($label)).$label;
		}
		return $encoded."\0";
	}

	/**
	 * A response to the query $id for self::Name: the question, then the
	 * given answer records (already encoded).
	 */
	private static function response($id, array $answers, $rcode = 0)
	{
		return pack('nnnnnn', $id, 0x8180 | $rcode, 1, count($answers), 0, 0).
			self::encodeName(self::Name).pack('nn', 12, 1).implode('', $answers);
	}

	private static function record($type, $rdata, $owner = "\xc0\x0c")
	{
		return $owner.pack('nnNn', $type, 1, 3600, strlen($rdata)).$rdata;
	}

	public function testPtrNames()
	{
		$this->assertSame('5.113.0.203.in-addr.arpa', DnsHelper::ptrName('203.0.113.5'));
		$this->assertSame('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
			DnsHelper::ptrName('2001:db8::1'));
		$this->assertSame(DnsHelper::ptrName('2001:db8::1'), DnsHelper::ptrName('2001:DB8:0::1'));
		$this->assertNull(DnsHelper::ptrName('not an address'));
		$this->assertNull(DnsHelper::ptrName(''));
	}

	public function testQuery()
	{
		$query = DnsHelper::buildQuery(0x1234, self::Name);
		$this->assertSame(pack('nnnnnn', 0x1234, 0x0100, 1, 0, 0, 0).self::encodeName(self::Name).pack('nn', 12, 1), $query);
	}

	public function testPtrRecordIsRead()
	{
		$host = self::encodeName('host.example.org');
		$this->assertSame('host.example.org', DnsHelper::parsePtrResponse(self::response(7, array(self::record(12, $host))), 7));
		// compressed: "mail" + pointer to "example.org" of an earlier record
		$cname = self::record(5, self::encodeName('5.0/24.113.0.203.in-addr.arpa'));
		$ptr = self::record(12, "\x04mail".self::encodeName('example.org'));
		$packet = self::response(7, array($cname, $ptr));
		$this->assertSame('mail.example.org', DnsHelper::parsePtrResponse($packet, 7), 'after the CNAME of a classless delegation');
		$offset = strpos($packet, "\x07example");
		$packet = self::response(7, array(self::record(12, "\x04host".self::encodeName('example.org')),
			self::record(12, "\x03www\xc0".chr($offset))));
		$this->assertSame('host.example.org', DnsHelper::parsePtrResponse($packet, 7), 'the first record');
	}

	public function testNoRecord()
	{
		$this->assertNull(DnsHelper::parsePtrResponse(self::response(7, array()), 7));
		$this->assertNull(DnsHelper::parsePtrResponse(self::response(7, array(), 3), 7), 'NXDOMAIN');
		$this->assertNull(DnsHelper::parsePtrResponse(self::response(7, array(), 2), 7), 'SERVFAIL');
		$this->assertNull(DnsHelper::parsePtrResponse(self::response(7, array(self::record(5, self::encodeName('x.example')))), 7),
			'a CNAME only');
	}

	public function testWhatIsNoResponseToTheQuery()
	{
		$good = self::response(7, array(self::record(12, self::encodeName('host.example.org'))));
		$this->assertFalse(DnsHelper::parsePtrResponse($good, 8), 'another id');
		$this->assertFalse(DnsHelper::parsePtrResponse(DnsHelper::buildQuery(7, self::Name), 7), 'a query, not a response');
		$this->assertFalse(DnsHelper::parsePtrResponse('', 7));
		$this->assertFalse(DnsHelper::parsePtrResponse(substr($good, 0, 11), 7));
		$this->assertFalse(DnsHelper::parsePtrResponse(substr($good, 0, -5), 7), 'cut off');
		// a pointer to itself
		$loop = pack('nnnnnn', 7, 0x8180, 1, 0, 0, 0)."\xc0\x0c".pack('nn', 12, 1);
		$this->assertFalse(DnsHelper::parsePtrResponse($loop, 7));
		// a record longer than the packet
		$this->assertFalse(DnsHelper::parsePtrResponse(self::response(7, array("\xc0\x0c".pack('nnNn', 12, 1, 0, 200).'x')), 7));
		// a host name of more than 255 bytes is none
		$long = str_repeat("\x3f".str_repeat('a', 63), 5)."\0";
		$this->assertNull(DnsHelper::parsePtrResponse(self::response(7, array(self::record(12, $long))), 7));
	}

	public function testNameservers()
	{
		$file = tempnam(sys_get_temp_dir(), 'resolv');
		try
		{
			file_put_contents($file, "# comment\nsearch example.org\nnameserver 192.0.2.53\n".
				"nameserver  2001:db8::53\nnameserver fe80::1%eth0\nnameserver nonsense\nnameserver 192.0.2.54\n");
			$this->assertSame(array('udp://192.0.2.53:53', 'udp://[2001:db8::53]:53', 'udp://[fe80::1]:53'),
				DnsHelper::nameservers($file));
		}
		finally
		{
			unlink($file);
		}
		$this->assertSame(array(), DnsHelper::nameservers('/does/not/exist'));
	}

	public function testNoLookupWithoutNameServer()
	{
		$this->assertFalse(DnsHelper::reverseLookup('203.0.113.5', 1.0, array()));
		$this->assertFalse(DnsHelper::reverseLookup('nonsense', 1.0, array('udp://127.0.0.1:53')));
	}

	/**
	 * Runs a name server on a port of localhost in another process: it
	 * answers the first query with a PTR record for $host, or ($host null)
	 * not at all. Returns the process and its address.
	 */
	private function startServer($host)
	{
		$script = '$s = stream_socket_server("udp://127.0.0.1:0", $e, $m, STREAM_SERVER_BIND);
echo stream_socket_get_name($s, false), "\n";
$q = stream_socket_recvfrom($s, 512, 0, $peer);
$host = '.var_export($host, true).';
if ($host !== null) {
	$question = substr($q, 12);
	$name = "";
	foreach (explode(".", $host) as $l) { $name .= chr(strlen($l)).$l; }
	$name .= "\0";
	stream_socket_sendto($s, substr($q, 0, 2).pack("nnnnn", 0x8180, 1, 1, 0, 0).$question.
		"\xc0\x0c".pack("nnNn", 12, 1, 60, strlen($name)).$name, 0, $peer);
}
sleep(5);';
		$process = proc_open(array(PHP_BINARY, '-r', $script), array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes);
		$this->assertIsResource($process);
		$address = trim((string) fgets($pipes[1]));
		$this->assertMatchesRegularExpression('/^127\.0\.0\.1:\d+$/', $address);
		return array($process, 'udp://'.$address);
	}

	public function testLookupAgainstAServer()
	{
		list($process, $server) = $this->startServer('host.example.org');
		try
		{
			$this->assertSame('host.example.org', DnsHelper::reverseLookup('203.0.113.5', 2.0, array($server)));
		}
		finally
		{
			proc_terminate($process);
			proc_close($process);
		}
	}

	public function testLookupGivesUpInTime()
	{
		// the owner of an address controls its reverse zone, and can make
		// the lookup hang: it must not take longer than allowed
		list($process, $server) = $this->startServer(null);
		try
		{
			$start = microtime(true);
			$this->assertNull(DnsHelper::reverseLookup('203.0.113.5', 0.5, array($server, $server)));
			$elapsed = microtime(true) - $start;
			$this->assertGreaterThanOrEqual(0.45, $elapsed);
			$this->assertLessThan(1.5, $elapsed, 'for all servers together');
		}
		finally
		{
			proc_terminate($process);
			proc_close($process);
		}
	}

	public function testUnreachableServerIsNoRecord()
	{
		// nobody listens there: the lookup ends at once, as no record
		$probe = stream_socket_server('udp://127.0.0.1:0', $errno, $error, STREAM_SERVER_BIND);
		$address = stream_socket_get_name($probe, false);
		fclose($probe);
		$start = microtime(true);
		$this->assertNull(DnsHelper::reverseLookup('203.0.113.5', 1.0, array('udp://'.$address)));
		$this->assertLessThan(1.5, microtime(true) - $start);
	}
}
