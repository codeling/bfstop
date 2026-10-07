<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Support;

/**
 * Writes a minimal MaxMind DB file (IPv4 only, 24 bit records), so that the
 * vendored reader (src/Helper/Geo) can be tested with a real lookup without
 * shipping a third-party database. See the MaxMind DB specification,
 * https://maxmind.github.io/MaxMind-DB/.
 */
class MmdbBuilder
{
	/**
	 * @param array $entries CIDR (e.g. "203.0.113.0/24") => record (nested
	 *                       arrays of strings and integers); the networks must
	 *                       not overlap
	 * @return string the contents of the database file
	 */
	public static function build(array $entries): string
	{
		$nodes = array(array(null, null));
		$data = '';
		foreach ($entries as $cidr => $record)
		{
			[$ip, $bits] = explode('/', $cidr);
			$bits = (int) $bits;
			$address = inet_pton($ip);
			$offset = strlen($data);
			$data .= self::encode($record);
			$node = 0;
			for ($i = 0; $i < $bits; ++$i)
			{
				$bit = (ord($address[$i >> 3]) >> (7 - ($i & 7))) & 1;
				if ($i === $bits - 1)
				{
					$nodes[$node][$bit] = array('data' => $offset);
					break;
				}
				if (!is_int($nodes[$node][$bit]))
				{
					$nodes[] = array(null, null);
					$nodes[$node][$bit] = count($nodes) - 1;
				}
				$node = $nodes[$node][$bit];
			}
		}
		$nodeCount = count($nodes);
		$tree = '';
		foreach ($nodes as $node)
		{
			foreach ($node as $record)
			{
				$value = $record === null ? $nodeCount
					: (is_int($record) ? $record : $nodeCount + 16 + $record['data']);
				$tree .= substr(pack('N', $value), 1);
			}
		}
		$metadata = array(
			'binary_format_major_version' => 2,
			'binary_format_minor_version' => 0,
			'build_epoch' => 1,
			'database_type' => 'BFStop-Test',
			'description' => array('en' => 'test database'),
			'ip_version' => 4,
			'languages' => array('en'),
			'node_count' => $nodeCount,
			'record_size' => 24,
		);
		return $tree.str_repeat("\0", 16).$data."\xAB\xCD\xEFMaxMind.com".self::encode($metadata);
	}

	private static function size(int $type, int $size): string
	{
		if ($size >= 29)
		{
			throw new \InvalidArgumentException('values this big are not needed by the tests');
		}
		return chr(($type << 5) | $size);
	}

	private static function encode($value): string
	{
		if (is_string($value))
		{
			return self::size(2, strlen($value)).$value;
		}
		if (is_int($value))
		{
			$bytes = $value === 0 ? '' : ltrim(pack('N', $value), "\0");
			return self::size(6, strlen($bytes)).$bytes;
		}
		if (is_array($value) && array_is_list($value))
		{
			// extended type 11 (array): type 0 in the control byte, then type - 7
			$out = chr(count($value))."\x04";
			foreach ($value as $item)
			{
				$out .= self::encode($item);
			}
			return $out;
		}
		$out = self::size(7, count($value));
		foreach ($value as $key => $item)
		{
			$out .= self::encode((string) $key).self::encode($item);
		}
		return $out;
	}
}
