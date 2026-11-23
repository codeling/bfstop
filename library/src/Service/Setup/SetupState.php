<?php
/*
 * @package BFStop Library (lib_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Service\Setup;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Repository\StateRepository;

/**
 * Where the setup assistant stands (rows of #__bfstop_state): whether it
 * runs for a new installation or after an update (and from which version),
 * the steps done or skipped, why the update disabled the plugin, what the
 * update found and did, the proxy setup the administrator confirmed, the
 * mismatches dismissed, and when protection was activated.
 *
 * The plugin's installer script writes the main row too, without this class
 * (the classes of the version being replaced may be the ones loaded while it
 * runs), in the same form: a test checks that this reads what it writes.
 *
 * A row holds at most 255 characters, so the parts which grow have rows of
 * their own: the steps (Steps) and the dismissed mismatches (Dismissed). Only
 * the scenario and the names of headers are kept, never an address.
 */
final class SetupState
{
	/** the row with the mode, the version updated from, what the update found and did */
	public const Name = 'setup';
	/** the row with the steps which are not pending */
	public const Steps = 'setupSteps';
	/** the row with the fingerprints of the dismissed mismatches */
	public const Dismissed = 'setupDismissed';

	public const ModeInstall = 'install';
	public const ModeUpgrade = 'upgrade';

	public const Pending = 'pending';
	public const Done = 'done';
	public const Skipped = 'skipped';

	// the steps of the assistant (see the plan, docs/setup-assistant-plan.md)
	public const StepProxy = 'proxy';
	public const StepBlockMode = 'blockMode';

	/** the steps which have to be done before protection is activated */
	public const RequiredSteps = array(self::StepProxy, self::StepBlockMode);

	// why the update disabled the plugin: the request of the update came
	// through a proxy (from the browser), or Joomla's "Behind Load Balancer"
	// is on (an update from the command line has no request to look at)
	public const DisabledProxy = 'proxy';
	public const DisabledLoadBalancer = 'loadbalancer';

	// how many dismissed mismatches are kept (the oldest go first)
	private const MaxDismissed = 16;

	private array $main;
	private array $steps;
	private array $dismissed;
	private bool $exists;

	private function __construct(array $main, array $steps, array $dismissed, bool $exists)
	{
		$this->main = $main;
		$this->steps = $steps;
		$this->dismissed = $dismissed;
		$this->exists = $exists;
	}

	/**
	 * The state of the stored rows $rows (name => value, see
	 * StateRepository::getMany()).
	 */
	public static function fromRows(array $rows): self
	{
		$decode = function ($name) use ($rows)
		{
			$value = isset($rows[$name]) ? json_decode((string) $rows[$name], true) : null;
			return is_array($value) ? $value : array();
		};
		$steps = array();
		foreach ($decode(self::Steps) as $step => $status)
		{
			if (in_array($status, array(self::Done, self::Skipped), true))
			{
				$steps[(string) $step] = $status;
			}
		}
		$dismissed = array_values(array_filter(explode(',', (string) ($rows[self::Dismissed] ?? '')),
			fn ($fingerprint) => preg_match('/^[0-9a-f]{12}\z/', $fingerprint) === 1));
		return new self($decode(self::Name), $steps, $dismissed, isset($rows[self::Name]));
	}

	/** The state as it is stored: one query. */
	public static function load(StateRepository $state): self
	{
		return self::fromRows($state->getMany(array(self::Name, self::Steps, self::Dismissed)));
	}

	/** Stores the state (the rows which have something to hold). */
	public function save(StateRepository $state): void
	{
		foreach ($this->toRows() as $name => $value)
		{
			$state->set($name, $value);
		}
	}

	/**
	 * The rows of the state: name => value.
	 *
	 * @return array<string, string>
	 */
	public function toRows(): array
	{
		$main = $this->main;
		$json = json_encode((object) $main);
		// the header names are the only part of unknown length: they go first
		if (strlen($json) > 255)
		{
			unset($main['headers']);
			$json = json_encode((object) $main);
		}
		return array(
			self::Name => $json,
			self::Steps => json_encode((object) $this->steps),
			self::Dismissed => implode(',', $this->dismissed),
		);
	}

	/** Whether the main row is stored (an installation or update wrote it). */
	public function exists(): bool
	{
		return $this->exists;
	}

	/** ModeInstall or ModeUpgrade; an installation which wrote nothing counts as one. */
	public function mode(): string
	{
		return ($this->main['mode'] ?? '') === self::ModeUpgrade ? self::ModeUpgrade : self::ModeInstall;
	}

	/** The version the update replaced, null for an installation. */
	public function from(): ?string
	{
		return isset($this->main['from']) && $this->main['from'] !== '' ? (string) $this->main['from'] : null;
	}

	/** Whether the update replaced a version before 2.0.0 (1.x). */
	public function fromBefore200(): bool
	{
		return $this->mode() === self::ModeUpgrade && $this->from() !== null &&
			version_compare($this->from(), '2.0.0-dev', '<');
	}

	public function status(string $step): string
	{
		return $this->steps[$step] ?? self::Pending;
	}

	public function setStatus(string $step, string $status): void
	{
		if ($status === self::Pending)
		{
			unset($this->steps[$step]);
			return;
		}
		$this->steps[$step] = $status;
	}

	/** The required steps which are not done yet. */
	public function pendingRequiredSteps(): array
	{
		return array_values(array_filter(self::RequiredSteps, fn ($step) => $this->status($step) !== self::Done));
	}

	/** When protection was activated (a Unix timestamp), null if not yet. */
	public function completedAt(): ?int
	{
		return !empty($this->main['completed']) ? (int) $this->main['completed'] : null;
	}

	public function isCompleted(): bool
	{
		return $this->completedAt() !== null;
	}

	public function complete(?int $time = null): void
	{
		$this->main['completed'] = $time ?? time();
	}

	/** Why the update disabled the plugin (DisabledProxy, DisabledLoadBalancer), null if it didn't. */
	public function disabledReason(): ?string
	{
		return isset($this->main['disabled']) ? (string) $this->main['disabled'] : null;
	}

	/** The scenario the update detected (see ProxyDetector), null if it didn't look. */
	public function updateScenario(): ?string
	{
		return isset($this->main['scenario']) ? (string) $this->main['scenario'] : null;
	}

	/** The names of the forwarding headers the request of the update carried. */
	public function updateHeaders(): array
	{
		return array_values(array_map('strval', (array) ($this->main['headers'] ?? array())));
	}

	/** Whether the settings the update replaced delayed the response to failed logins. */
	public function delaysRemoved(): bool
	{
		return !empty($this->main['delays']);
	}

	/** Whether the update could not rewrite the block section of an earlier version in .htaccess. */
	public function htaccessNotRewritten(): bool
	{
		return !empty($this->main['htaccess']);
	}

	/** The fingerprint of the proxy setup the administrator confirmed (see ProxyDetector::fingerprint()). */
	public function confirmedFingerprint(): ?string
	{
		return isset($this->main['fp']) ? (string) $this->main['fp'] : null;
	}

	public function confirmFingerprint(string $fingerprint): void
	{
		$this->main['fp'] = $fingerprint;
	}

	public function isDismissed(string $fingerprint): bool
	{
		return in_array($fingerprint, $this->dismissed, true);
	}

	/** Dismisses the mismatch with the fingerprint $fingerprint (see ProxyMismatch). */
	public function dismiss(string $fingerprint): void
	{
		if (preg_match('/^[0-9a-f]{12}\z/', $fingerprint) !== 1 || $this->isDismissed($fingerprint))
		{
			return;
		}
		$this->dismissed[] = $fingerprint;
		$this->dismissed = array_slice($this->dismissed, -self::MaxDismissed);
	}

	/** @return string[] */
	public function dismissed(): array
	{
		return $this->dismissed;
	}
}
