<?php
/*
 * @package BFStop for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Library\Bfstop\Service\Setup\SetupState;
use PHPUnit\Framework\TestCase;

/**
 * The state of the setup assistant, in the rows of #__bfstop_state (each at
 * most 255 characters).
 */
class SetupStateTest extends TestCase
{
	public function testNothingStored()
	{
		$state = SetupState::fromRows(array());
		$this->assertFalse($state->exists());
		$this->assertSame(SetupState::ModeInstall, $state->mode());
		$this->assertNull($state->from());
		$this->assertFalse($state->isCompleted());
		$this->assertSame(SetupState::RequiredSteps, $state->pendingRequiredSteps());
		$this->assertSame(SetupState::Pending, $state->status(SetupState::StepProxy));
	}

	public function testWhatTheUpdateWrites()
	{
		$state = SetupState::fromRows(array(SetupState::Name => json_encode(array('mode' => 'upgrade', 'from' => '1.5.2',
			'disabled' => 'proxy', 'scenario' => 'B', 'headers' => array('HTTP_X_FORWARDED_FOR'), 'delays' => 1, 'htaccess' => 1))));
		$this->assertTrue($state->exists());
		$this->assertSame(SetupState::ModeUpgrade, $state->mode());
		$this->assertSame('1.5.2', $state->from());
		$this->assertTrue($state->fromBefore200());
		$this->assertSame(SetupState::DisabledProxy, $state->disabledReason());
		$this->assertSame('B', $state->updateScenario());
		$this->assertSame(array('HTTP_X_FORWARDED_FOR'), $state->updateHeaders());
		$this->assertTrue($state->delaysRemoved());
		$this->assertTrue($state->htaccessNotRewritten());
		$this->assertFalse(SetupState::fromRows(array(SetupState::Name => '{"mode":"upgrade","from":"2.0.0-rc1"}'))->fromBefore200());
	}

	public function testStepsCompletionAndRoundTrip()
	{
		$state = SetupState::fromRows(array());
		$state->setStatus(SetupState::StepProxy, SetupState::Done);
		$this->assertSame(array(SetupState::StepBlockMode), $state->pendingRequiredSteps());
		$state->setStatus(SetupState::StepBlockMode, SetupState::Skipped);
		$this->assertSame(array(SetupState::StepBlockMode), $state->pendingRequiredSteps(), 'a required step has to be done');
		$state->setStatus(SetupState::StepBlockMode, SetupState::Done);
		$state->confirmFingerprint('0123456789ab');
		$state->complete(1700000000);
		$copy = SetupState::fromRows($state->toRows());
		$this->assertSame(array(), $copy->pendingRequiredSteps());
		$this->assertSame(1700000000, $copy->completedAt());
		$this->assertSame('0123456789ab', $copy->confirmedFingerprint());
		$copy->setStatus(SetupState::StepProxy, SetupState::Pending);
		$this->assertSame(array(SetupState::StepProxy), $copy->pendingRequiredSteps());
	}

	public function testRowsStayWithinTheirColumn()
	{
		$state = SetupState::fromRows(array(SetupState::Name => json_encode(array('mode' => 'upgrade', 'from' => '2.0.0-beta12',
			'disabled' => 'loadbalancer', 'scenario' => 'E', 'delays' => 1, 'htaccess' => 1, 'fp' => '0123456789ab',
			'completed' => 1700000000, 'headers' => array_merge(array('HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_X_FORWARDED',
			'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP',
			'HTTP_TRUE_CLIENT_IP', 'HTTP_FASTLY_CLIENT_IP'))))));
		foreach (array(SetupState::StepProxy, SetupState::StepBlockMode, SetupState::StepCleanup, SetupState::StepHtaccess,
			SetupState::StepNotify, SetupState::StepNotifyMeaning, SetupState::StepParts, SetupState::StepRateLimit) as $step)
		{
			// the longest status of every step
			$state->setStatus($step, SetupState::Skipped);
		}
		for ($i = 0; $i < 40; ++$i)
		{
			$state->dismiss(substr(sha1((string) $i), 0, 12));
		}
		$state->dismiss('not a fingerprint');
		foreach ($state->toRows() as $name => $value)
		{
			$this->assertLessThanOrEqual(255, strlen($value), $name);
		}
		$copy = SetupState::fromRows($state->toRows());
		$this->assertSame(1700000000, $copy->completedAt(), 'the header names go first');
		$this->assertCount(16, $copy->dismissed());
		$this->assertTrue($copy->isDismissed(substr(sha1('39'), 0, 12)), 'the newest are kept');
		$this->assertFalse($copy->isDismissed(substr(sha1('0'), 0, 12)));
	}
}
