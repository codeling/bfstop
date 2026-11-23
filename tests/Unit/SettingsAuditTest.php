<?php
/*
 * @package BFStop for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Library\Bfstop\Service\Setup\SettingsAudit;
use PHPUnit\Framework\TestCase;

/**
 * The fixes the setup assistant proposes for stored values which keep the
 * settings from being saved. Which values those are is found by the
 * settings form itself, which needs Joomla: see the integration test
 * SetupTest, with settings of 1.5.2.
 */
class SettingsAuditTest extends TestCase
{
	public function testProposedFixes()
	{
		// 1.5.2 took a stray ";", commas, and anything that wasn't an address
		$this->assertSame('a@example.org;b@example.org',
			SettingsAudit::proposedFix('emailaddress', 'a@example.org;b@example.org;', array()));
		$this->assertSame('a@example.org;b@example.org',
			SettingsAudit::proposedFix('emailaddress', 'a@example.org, b@example.org, nobody', array()));
		$this->assertSame('', SettingsAudit::proposedFix('emailaddress', 'nobody', array()));
		$this->assertSame('full', SettingsAudit::proposedFix('blockMode', 'htaccess', array()));
		$this->assertSame('0', SettingsAudit::proposedFix('notifyBlockedUser', '1', array()));
		$this->assertSame('7', SettingsAudit::proposedFix('riskMinBlockNumber', '9', array('blockNumber' => '7')));
		$this->assertSame('10', SettingsAudit::proposedFix('riskMinBlockNumber', '12', array()), 'the default threshold');
		$this->assertSame('', SettingsAudit::proposedFix('htaccessPath', '/no/such/dir', array()));
		$this->assertSame('1440', SettingsAudit::proposedFix('blockDuration', '7', array()), 'an option no longer offered');
	}
}
