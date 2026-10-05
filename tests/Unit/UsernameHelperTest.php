<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Plugin\System\Bfstop\Helper\UsernameHelper;
use PHPUnit\Framework\TestCase;

class UsernameHelperTest extends TestCase
{
	public function testReadableUsernamesAreKept()
	{
		$this->assertSame('Admin', UsernameHelper::forStorage('Admin', UsernameHelper::ModeHash, true, 'key'));
	}

	public function testPlainModeKeepsEverything()
	{
		$this->assertSame('hunter2', UsernameHelper::forStorage('hunter2', UsernameHelper::ModePlain, false, 'key'));
	}

	public function testUnknownUsernamesAreHashed()
	{
		$stored = UsernameHelper::forStorage('hunter2', UsernameHelper::ModeHash, false, 'key');
		$this->assertMatchesRegularExpression('/^\[unknown:[0-9a-f]{16}\]$/', $stored);
		$this->assertStringNotContainsString('hunter2', $stored);
	}

	public function testHashIsStableAndCaseInsensitive()
	{
		$a = UsernameHelper::forStorage('Hunter2', UsernameHelper::ModeHash, false, 'key');
		$this->assertSame($a, UsernameHelper::forStorage('hunter2', UsernameHelper::ModeHash, false, 'key'));
		$this->assertNotSame($a, UsernameHelper::forStorage('hunter3', UsernameHelper::ModeHash, false, 'key'));
	}

	public function testHashDependsOnTheSiteKey()
	{
		// so values can't be matched against a precomputed table of passwords
		$this->assertNotSame(
			UsernameHelper::forStorage('hunter2', UsernameHelper::ModeHash, false, 'key1'),
			UsernameHelper::forStorage('hunter2', UsernameHelper::ModeHash, false, 'key2'));
	}

	public function testMultibyteUsername()
	{
		$this->assertMatchesRegularExpression('/^\[unknown:[0-9a-f]{16}\]$/',
			UsernameHelper::forStorage('Пароль🔑', UsernameHelper::ModeHash, false, 'key'));
	}
}
