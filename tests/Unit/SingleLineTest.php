<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use PHPUnit\Framework\TestCase;

class SingleLineTest extends TestCase
{
	public function testLineBreaksAndOtherControlCharactersBecomeSpaces()
	{
		$this->assertSame('bob 2020-01-01T00:00:00+00:00 INFO forged',
			LoggerHelper::singleLine("bob\r\n2020-01-01T00:00:00+00:00\tINFO\x00forged"));
		$this->assertSame(' ', LoggerHelper::singleLine("\n\n\r"));
	}

	public function testOrdinaryTextIsKept()
	{
		$this->assertSame('Zoë 管理者 <b>', LoggerHelper::singleLine('Zoë 管理者 <b>'));
		$this->assertSame('', LoggerHelper::singleLine(null));
	}
}
