<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ActionLogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\IpValidateHelper;
use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\UnblockHelper;
use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Origin;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\Setup\ProxyCleanup;
use Codeling\Library\Bfstop\Service\Setup\ProxyDetector;
use Codeling\Library\Bfstop\Service\Setup\ProxyMismatch;
use Codeling\Library\Bfstop\Service\Setup\SettingsAudit;
use Codeling\Library\Bfstop\Service\Setup\SetupState;
use Codeling\Library\Bfstop\Service\Setup\UsernameHashing;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Cache\CacheControllerFactoryInterface;
use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Http\HttpFactory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Factory\MVCFactory;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;
use Joomla\Registry\Registry;

/**
 * The setup assistant: what it detects, what it proposes, and what it does
 * when the administrator confirms a step - always through the settings model
 * (SettingsModel::validate() and save()), so that the rules of the settings
 * page, the User Actions Log, the nginx deny file and the tidying of the
 * .htaccess file apply as when the settings page saves. Activating
 * protection enables the system plugin, once the required steps are done
 * (see missingForActivation()). Its state is the library's SetupState.
 *
 * Used by the assistant's pages and by the console command bfstop:setup
 * (which has no request: no proxy check, see confirmProxy()).
 */
class SetupModel extends BaseDatabaseModel
{
	/** the pages of the assistant, in their order (not all are shown, see pages()) */
	public const Pages = array('overview', 'proxy', 'cleanup', 'blockmode', 'htaccess', 'notify', 'parts', 'privacy',
		'ratelimit', 'scheduler', 'summary');

	/** the step of the setup state each page stands for (the others stand for none) */
	public const PageSteps = array('proxy' => SetupState::StepProxy, 'cleanup' => SetupState::StepCleanup,
		'blockmode' => SetupState::StepBlockMode, 'htaccess' => SetupState::StepHtaccess,
		'notify' => SetupState::StepNotify, 'parts' => SetupState::StepParts, 'privacy' => SetupState::StepPrivacy,
		'ratelimit' => SetupState::StepRateLimit, 'scheduler' => SetupState::StepScheduler);

	/** the settings each step of a page of settings saves (see saveFields()) */
	public const StepFields = array(
		SetupState::StepNotify => array('emailaddress', 'userID', 'groupNotificationEnabled', 'userGroup',
			'notifyBlockedUser', 'notifyBlockedNumber', 'notifyFailedNumber', 'notifyFailedOnlyExisting'),
		SetupState::StepParts => array('enabledForOrigin'),
		SetupState::StepPrivacy => array('deleteOld', 'unknownUsernameMode'),
	);

	/** Cloudflare's address ranges, which the proxy step fetches when asked to */
	public const CloudflareRanges = array('https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6');

	private ?SetupState $setup = null;
	private ?Repositories $repositories = null;
	// the settings as this model saved them last (Joomla keeps the params of
	// the components it loaded for the whole request), see storedParams()
	private ?array $saved = null;

	private function repositories(): Repositories
	{
		return $this->repositories ??= new Repositories(LogHelper::getLogger(), $this->getDatabase());
	}

	/** The state of the setup (one query, then kept). */
	public function setupState(): SetupState
	{
		return $this->setup ??= SetupState::load($this->repositories()->state());
	}

	private function saveSetupState(): void
	{
		$this->setupState()->save($this->repositories()->state());
	}

	/** The settings as they are stored now. */
	public function storedParams(): array
	{
		return $this->saved ?? Settings::stored()->toArray();
	}

	private function settings(): Registry
	{
		return new Registry($this->storedParams());
	}

	/**
	 * The pages of the assistant for this site: those of the steps which
	 * only make sense after an update only then (the clean-up after the
	 * proxy fix behind a proxy, the .htaccess section of an earlier version
	 * while the file has one, the rate limiting where the update removed
	 * delays which were in use, the privacy of the data of 1.x).
	 *
	 * @return string[]
	 */
	public function pages(): array
	{
		$setup = $this->setupState();
		$upgrade = $setup->mode() === SetupState::ModeUpgrade;
		$shown = array(
			'cleanup' => $upgrade && (Settings::bool($this->settings(), 'useProxy') ||
				$setup->status(SetupState::StepCleanup) !== SetupState::Pending),
			'htaccess' => $upgrade && ($this->legacyHtaccess()['present'] || $setup->htaccessNotRewritten()),
			'privacy' => $upgrade,
			'ratelimit' => $upgrade && $setup->delaysRemoved(),
		);
		return array_values(array_filter(self::Pages, fn ($page) => $shown[$page] ?? true));
	}

	/** The page after $page (the last one: itself). */
	public function nextPage(string $page): string
	{
		$pages = $this->pages();
		$index = array_search($page, $pages, true);
		return $index === false ? 'summary' : $pages[min($index + 1, count($pages) - 1)];
	}

	/** Marks the optional step $step as skipped. */
	public function skip(string $step): bool
	{
		if (in_array($step, SetupState::RequiredSteps, true) || !in_array($step, self::PageSteps, true))
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_ERROR_SKIP'));
			return false;
		}
		$this->setupState()->setStatus($step, SetupState::Skipped);
		$this->saveSetupState();
		return true;
	}

	/** Marks the step $step, which saves no settings (it explains), as done. */
	public function acknowledge(string $step): bool
	{
		if (!in_array($step, array(SetupState::StepRateLimit, SetupState::StepScheduler), true))
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_ERROR_SKIP'));
			return false;
		}
		$this->setupState()->setStatus($step, SetupState::Done);
		$this->saveSetupState();
		ActionLogHelper::log('setup_step_applied', array('step' => $step));
		return true;
	}

	/**
	 * Saves the settings $params (as the settings form sends them) of the
	 * step $step - only those the step is about (StepFields) - with the
	 * fixes $fixes, see apply().
	 */
	public function saveFields(string $step, array $params, array $fixes = array()): bool
	{
		if (!isset(self::StepFields[$step]))
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_ERROR_SKIP'));
			return false;
		}
		$params = array_intersect_key($params, array_flip(self::StepFields[$step]));
		if (in_array('enabledForOrigin', self::StepFields[$step], true) &&
			Origin::mask($params['enabledForOrigin'] ?? array()) === 0)
		{
			// the form requires a part: without one, BFStop would protect nothing
			$this->setError(Text::_('COM_BFSTOP_SETUP_PARTS_ERROR_NONE'));
			return false;
		}
		if (!$this->apply($step, SettingsModel::paramsForStorage($params), $fixes))
		{
			return false;
		}
		if ($step === SetupState::StepNotify && $this->notifyMeaningChanged())
		{
			// the decision about the changed meaning of the unblock mails is made with it
			$this->setupState()->setStatus(SetupState::StepNotifyMeaning, SetupState::Done);
			$this->saveSetupState();
		}
		return true;
	}

	/**
	 * Whether the notifications step has to explain that the unblock mails
	 * ("notifyBlockedUser") changed their meaning: 1 meant "for any address"
	 * in 1.x and means "only for addresses the user logged in from before"
	 * now - and the update came from 1.x, with the setting on.
	 */
	public function notifyMeaningChanged(): bool
	{
		return $this->setupState()->fromBefore200() && Settings::int($this->settings(), 'notifyBlockedUser') !== 0;
	}

	/** How many users have a Joomla API token (enabled): the context of the API in the protected parts. */
	public function apiTokenUsers(): int
	{
		try
		{
			$db = $this->getDatabase();
			$query = $db->createQuery()
				->select('COUNT(DISTINCT '.$db->quoteName('t.user_id').')')
				->from($db->quoteName('#__user_profiles', 't'))
				->innerJoin($db->quoteName('#__user_profiles', 'e').' ON '.$db->quoteName('e.user_id').' = '.
					$db->quoteName('t.user_id'))
				->where($db->quoteName('t.profile_key').' = '.$db->quote('joomlatoken.token'))
				->where($db->quoteName('e.profile_key').' = '.$db->quote('joomlatoken.enabled'))
				->where($db->quoteName('e.profile_value').' = '.$db->quote('1'));
			$db->setQuery($query);
			return (int) $db->loadResult();
		}
		catch (\Throwable $e)
		{
			return 0;
		}
	}

	/** The trusted proxies of the saved settings (none while proxy support is off). */
	private function trustedProxies(): array
	{
		$proxy = ProxyDetector::proxySettings($this->settings());
		return $proxy['useProxy'] ? $proxy['trusted'] : array();
	}

	/** What the clean-up after the proxy fix finds, see ProxyCleanup::findings(). */
	public function cleanupFindings(): array
	{
		return (new ProxyCleanup($this->repositories()))->findings($this->trustedProxies());
	}

	/**
	 * The blocks which look like a proxy's (see ProxyCleanup::suspiciousBlocks()),
	 * for the request $server (default: this one).
	 */
	public function suspiciousBlocks(?array $server = null): array
	{
		$server = $server ?? $_SERVER;
		return (new ProxyCleanup($this->repositories()))->suspiciousBlocks((string) ($server['REMOTE_ADDR'] ?? ''));
	}

	/**
	 * The clean-up after the proxy fix (see ProxyCleanup::clean()); the
	 * .htaccess file and the nginx deny file lose the blocks lifted.
	 */
	public function cleanup(): bool
	{
		if (count($this->trustedProxies()) === 0)
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_CLEANUP_ERROR_NO_PROXY'));
			return false;
		}
		$removed = (new ProxyCleanup($this->repositories()))->clean($this->trustedProxies());
		if (count($removed['blockIds']) > 0)
		{
			UnblockHelper::removeLiftedHtaccessBlocks($this->repositories()->logger());
			ActionLogHelper::log('blocks_lifted', array('ipaddresses' => $removed['blocks']));
		}
		$this->setupState()->setStatus(SetupState::StepCleanup, SetupState::Done);
		$this->saveSetupState();
		ActionLogHelper::log('setup_step_applied', array('step' => SetupState::StepCleanup));
		return true;
	}

	/**
	 * The .htaccess file of the settings, and whether it still has the block
	 * section of an earlier version (which lets everybody who isn't blocked
	 * past the other access controls of the directory), with the section as
	 * it is and as it would be rewritten.
	 *
	 * @return array{file: string, present: bool, current: string[], proposed: string[]}
	 */
	public function legacyHtaccess(): array
	{
		$htaccess = new HtaccessHelper(HtaccessHelper::resolvePath(Settings::string($this->settings(), 'htaccessPath')), null);
		try
		{
			$present = is_file($htaccess->getFileName()) && $htaccess->hasLegacySection();
			$preview = $present ? $htaccess->sectionPreview() : array('current' => array(), 'proposed' => array());
		}
		catch (\Throwable $e)
		{
			$present = false;
			$preview = array('current' => array(), 'proposed' => array());
		}
		return array('file' => $htaccess->getFileName(), 'present' => $present) + $preview;
	}

	/** Rewrites the block section of an earlier version in .htaccess (see HtaccessHelper::upgradeFormat()). */
	public function upgradeHtaccess(): bool
	{
		$htaccess = new HtaccessHelper(HtaccessHelper::resolvePath(Settings::string($this->settings(), 'htaccessPath')),
			$this->repositories()->logger());
		if (!$htaccess->upgradeFormat())
		{
			$this->setError(Text::sprintf('COM_BFSTOP_SETUP_HTACCESS_ERROR_WRITE',
				htmlspecialchars($htaccess->getFileName(), ENT_QUOTES, 'UTF-8')));
			return false;
		}
		$this->setupState()->setStatus(SetupState::StepHtaccess, SetupState::Done);
		$this->saveSetupState();
		ActionLogHelper::log('setup_step_applied', array('step' => SetupState::StepHtaccess));
		return true;
	}

	/**
	 * What the privacy step shows: how many failed logins there are and when
	 * the oldest was, and the log file (which holds usernames too).
	 *
	 * @return array{count: int, oldest: string|null, logFile: string, logBytes: int}
	 */
	public function privacyFacts(): array
	{
		$logFile = rtrim((string) Factory::getApplication()->get('log_path'), '/\\').'/plg_system_bfstop.log.php';
		return $this->repositories()->failedLogins()->extent() + array(
			'logFile' => $logFile,
			'logBytes' => is_file($logFile) ? (int) filesize($logFile) : 0,
		);
	}

	/**
	 * Hashes the plain usernames earlier versions stored (see
	 * UsernameHashing), in rounds, for at most $seconds: of the failed logins
	 * first ($table UsernameHashing::FailedLogins), then of the statistics,
	 * going on after the username $after.
	 *
	 * @return array{table: string, after: string, done: bool, hashed: int}
	 *         where to go on, unless done
	 */
	public function hashUsernames(string $table, string $after, float $seconds = 5.0): array
	{
		$hashing = new UsernameHashing($this->repositories(), $this->settings(),
			(string) Factory::getApplication()->get('secret', ''));
		$table = $table === UsernameHashing::Statistics ? $table : UsernameHashing::FailedLogins;
		$until = microtime(true) + $seconds;
		$hashed = 0;
		do
		{
			$round = $hashing->round($table, $after);
			$hashed += $round['hashed'];
			if ($round['last'] !== null)
			{
				$after = $round['last'];
				continue;
			}
			if ($table === UsernameHashing::Statistics)
			{
				ActionLogHelper::log('usernames_hashed');
				return array('table' => $table, 'after' => '', 'done' => true, 'hashed' => $hashed);
			}
			$table = UsernameHashing::Statistics;
			$after = '';
		}
		while (microtime(true) < $until);
		return array('table' => $table, 'after' => $after, 'done' => false, 'hashed' => $hashed);
	}

	/**
	 * What the scheduler step shows: whether the task plugin is enabled,
	 * the maintenance tasks (title, state, last and next run), and whether
	 * the Task Scheduler runs tasks in visitors' requests (its "lazy
	 * scheduler"; otherwise a cron job has to).
	 *
	 * @return array{plugin: bool, tasks: object[], lazy: bool}
	 */
	public function schedulerFacts(): array
	{
		$db = $this->getDatabase();
		$facts = array('plugin' => false, 'tasks' => array(), 'lazy' => true);
		try
		{
			$db->setQuery($db->createQuery()
				->select($db->quoteName('enabled'))
				->from($db->quoteName('#__extensions'))
				->where($db->quoteName('type').' = '.$db->quote('plugin'))
				->where($db->quoteName('folder').' = '.$db->quote('task'))
				->where($db->quoteName('element').' = '.$db->quote('bfstop')));
			$facts['plugin'] = (int) $db->loadResult() === 1;
			$db->setQuery($db->createQuery()
				->select($db->quoteName(array('id', 'title', 'state', 'last_execution', 'next_execution', 'times_failed')))
				->from($db->quoteName('#__scheduler_tasks'))
				->where($db->quoteName('type').' = '.$db->quote('bfstop.maintenance'))
				->order($db->quoteName('id')));
			$facts['tasks'] = $db->loadObjectList();
			$facts['lazy'] = (bool) ComponentHelper::getParams('com_scheduler')->get('lazy_scheduler.enabled', 1);
		}
		catch (\Throwable $e)
		{
			// what can't be read is shown as missing
		}
		return $facts;
	}

	/** Joomla's "Behind Load Balancer" (see ProxyDetector::loadBalancerHint()). */
	public static function behindLoadBalancer(): bool
	{
		return (bool) Factory::getApplication()->get('behind_loadbalancer', 0);
	}

	/** What the request $server (default: this one) tells about the proxy, see ProxyDetector::detect(). */
	public function detection(?array $server = null): array
	{
		return ProxyDetector::detect($server ?? $_SERVER, ProxyDetector::proxySettings($this->settings()), self::behindLoadBalancer());
	}

	/** The mismatches of the request $server (default: this one) and the settings, see ProxyMismatch. */
	public function mismatches(?array $server = null): array
	{
		return ProxyMismatch::check($server ?? $_SERVER, ProxyDetector::proxySettings($this->settings()), self::behindLoadBalancer(), $this->setupState());
	}

	/**
	 * The stored values which keep the settings from being saved, see
	 * SettingsAudit: shown with every step, and fixed with it.
	 */
	public function blockingValues(): array
	{
		$params = $this->storedParams();
		return SettingsAudit::blockingValues(SettingsModel::settingsForm(), SettingsModel::paramsForForm($params),
			SettingsModel::crossFieldErrors($params));
	}

	private function settingsModel(): SettingsModel
	{
		$factory = $this->getMVCFactory();
		$model = new SettingsModel(array('ignore_request' => true),
			$factory instanceof MVCFactory ? $factory : new MVCFactory('Codeling\\Component\\Bfstop'));
		$model->setDatabase($this->getDatabase());
		return $model;
	}

	/**
	 * Saves the settings $changes (name => value, as stored) of the step
	 * $step, with the fixes of the stored values which would keep them from
	 * being saved: $fixes (field => value) where the administrator changed
	 * the proposal, the proposal of SettingsAudit otherwise. Marks the step
	 * as done (unless it is null: only the fixes) and logs it in the User
	 * Actions Log.
	 *
	 * @return bool false if the settings model refused them (see getErrors())
	 */
	public function apply(?string $step, array $changes, array $fixes = array()): bool
	{
		$params = $this->storedParams();
		foreach ($this->blockingValues() as $field => $blocking)
		{
			$params[$field] = array_key_exists($field, $fixes) ? (string) $fixes[$field] : $blocking['fix'];
		}
		$params = array_merge($params, $changes);
		$model = $this->settingsModel();
		$valid = $model->validate(SettingsModel::settingsForm(), array('params' => SettingsModel::paramsForForm($params)));
		if ($valid === false || !$model->save($valid))
		{
			foreach ($model->getErrors() as $error)
			{
				$this->setError($error instanceof \Throwable ? $error->getMessage() : (string) $error);
			}
			return false;
		}
		$this->saved = SettingsModel::paramsForStorage($valid['params'] ?? array());
		if ($step !== null)
		{
			$this->setupState()->setStatus($step, SetupState::Done);
			$this->saveSetupState();
		}
		ActionLogHelper::log('setup_step_applied', array('step' => $step ?? 'fixes'));
		return true;
	}

	/**
	 * The proxy step, confirmed with "there is no proxy": BFStop takes the
	 * address the request comes from. Not where only headers BFStop can't
	 * read arrive (E: there is a proxy, whose header BFStop can't use), and
	 * behind a proxy or CDN (B, D) only with $acknowledged: the administrator
	 * says the site is reached directly all the same.
	 *
	 * @param array|null $server the request (null: none, the console)
	 */
	public function confirmNoProxy(bool $acknowledged, array $fixes = array(), ?array $server = null): bool
	{
		$detected = $server !== null ? $this->detection($server) : null;
		if ($detected !== null && $detected['scenario'] === ProxyDetector::Unsupported)
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_PROXY_ERROR_UNSUPPORTED'));
			return false;
		}
		if ($detected !== null && ProxyDetector::needsProxySettings($detected['scenario']) && !$acknowledged)
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_PROXY_ERROR_ACKNOWLEDGE'));
			return false;
		}
		if (!$this->apply(SetupState::StepProxy, array('useProxy' => '0'), $fixes))
		{
			return false;
		}
		$this->setupState()->confirmFingerprint(ProxyDetector::fingerprint($detected['scenario'] ?? ProxyDetector::Direct, null, false));
		$this->saveSetupState();
		return true;
	}

	/**
	 * The proxy step, confirmed with a proxy: the trusted proxies $trusted
	 * and the header $header. With a request ($server), only if the dry run
	 * (ProxyDetector::preview()) finds a client address in it, which the
	 * administrator confirmed to be their own ($confirmedAddress: the
	 * address the page showed them, which the settings must still give):
	 * settings which take the proxy for the client would block everybody.
	 * The console has no request to check them with (null).
	 */
	public function confirmProxy(string $header, string $trusted, ?string $confirmedAddress, array $fixes = array(),
		?array $server = null): bool
	{
		if (!in_array($header, IpHelper::KnownProxyHeaders, true))
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_PROXY_ERROR_HEADER'));
			return false;
		}
		if (count(IpHelper::parseTrustedProxies($trusted)) === 0)
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_PROXY_ERROR_TRUSTED'));
			return false;
		}
		$fingerprint = ProxyDetector::fingerprint(ProxyDetector::BehindProxy, $header, true);
		if ($server !== null)
		{
			$preview = ProxyDetector::preview($server, true, $header, $trusted);
			if ($preview['problem'] !== null)
			{
				$this->setError(Text::_('COM_BFSTOP_SETUP_PREVIEW_PROBLEM_'.strtoupper($preview['problem'])));
				return false;
			}
			if ($confirmedAddress === null || $confirmedAddress !== $preview['address'])
			{
				$this->setError(Text::_('COM_BFSTOP_SETUP_PROXY_ERROR_CONFIRM'));
				return false;
			}
			$fingerprint = ProxyDetector::fingerprint($this->detection($server)['scenario'], $header, true);
		}
		if (!$this->apply(SetupState::StepProxy, array('useProxy' => '1', 'proxyHeaderSource' => $header,
			'proxyIpAddress' => $trusted), $fixes))
		{
			return false;
		}
		$this->setupState()->confirmFingerprint($fingerprint);
		$this->saveSetupState();
		return true;
	}

	/**
	 * What the blocking-mode step says about the web server and the
	 * blocking mode: the server (HtaccessHelper::webServer()), the mode, the
	 * mode to recommend, and the warnings - nginx (never reads .htaccess),
	 * LiteSpeed (reads it, but differently), .htaccess behind a proxy
	 * (Apache compares the proxy's address), "Reporting Only" (no
	 * protection; after an update which removed the delays which protected
	 * the site until then, flagged as such).
	 *
	 * @return array{server: string, mode: string, recommended: string, warnings: string[], proxy: bool}
	 */
	public function blockModeAdvice(?array $server = null): array
	{
		$server = $server ?? $_SERVER;
		$webServer = HtaccessHelper::webServer($server['SERVER_SOFTWARE'] ?? '');
		$settings = $this->settings();
		$mode = Settings::string($settings, 'blockMode');
		$detected = $this->detection($server);
		$proxy = Settings::bool($settings, 'useProxy') ||
			in_array($detected['scenario'], array(ProxyDetector::BehindProxy, ProxyDetector::BehindCdn), true);
		$warnings = array();
		$recommended = in_array($mode, array('loginonly', 'full'), true) ? $mode : 'full';
		if ($webServer === HtaccessHelper::ServerNginx)
		{
			$warnings[] = 'nginx';
		}
		elseif ($webServer === HtaccessHelper::ServerLiteSpeed)
		{
			$warnings[] = 'litespeed';
		}
		if ($mode === 'htaccess')
		{
			if ($proxy)
			{
				$warnings[] = 'htaccessProxy';
			}
			elseif ($webServer !== HtaccessHelper::ServerNginx)
			{
				$recommended = 'htaccess';
			}
		}
		if ($mode === 'off')
		{
			$warnings[] = $this->setupState()->delaysRemoved() ? 'unprotected' : 'reportingOnly';
		}
		return array('server' => $webServer, 'mode' => $mode, 'recommended' => $recommended,
			'warnings' => $warnings, 'proxy' => $proxy);
	}

	/**
	 * The blocking-mode step, confirmed with the mode $mode (and, with
	 * "Full Site", the nginx deny file $nginxDenyFile). "Reporting Only"
	 * only with $offConfirmed: it doesn't protect anything.
	 */
	public function confirmBlockMode(string $mode, ?string $nginxDenyFile, bool $offConfirmed, array $fixes = array()): bool
	{
		if (!in_array($mode, array('off', 'loginonly', 'full', 'htaccess'), true))
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_BLOCKMODE_ERROR_MODE'));
			return false;
		}
		if ($mode === 'off' && !$offConfirmed)
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_BLOCKMODE_ERROR_OFF'));
			return false;
		}
		$changes = array('blockMode' => $mode);
		if ($mode === 'full' && $nginxDenyFile !== null)
		{
			$changes['nginxDenyFile'] = trim($nginxDenyFile);
		}
		return $this->apply(SetupState::StepBlockMode, $changes, $fixes);
	}

	/**
	 * What still keeps protection from being activated: the required steps
	 * not done (their names, see SetupState::RequiredSteps), 'blockingValues'
	 * (a stored value the settings page would refuse), 'modeUnfit' (blocking
	 * through .htaccess on nginx).
	 *
	 * @return string[]
	 */
	public function missingForActivation(?array $server = null): array
	{
		$missing = $this->setupState()->pendingRequiredSteps();
		if (count($this->blockingValues()) > 0)
		{
			$missing[] = 'blockingValues';
		}
		$server = $server ?? $_SERVER;
		if (Settings::string($this->settings(), 'blockMode') === 'htaccess' &&
			HtaccessHelper::webServer($server['SERVER_SOFTWARE'] ?? '') === HtaccessHelper::ServerNginx)
		{
			$missing[] = 'modeUnfit';
		}
		return $missing;
	}

	/** Whether the system plugin is installed and enabled (as stored, not as loaded for this request). */
	public function pluginEnabled(): bool
	{
		$db = $this->getDatabase();
		$query = $db->createQuery()
			->select($db->quoteName('enabled'))
			->from($db->quoteName('#__extensions'))
			->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
			->where($db->quoteName('folder') . ' = ' . $db->quote('system'))
			->where($db->quoteName('element') . ' = ' . $db->quote('bfstop'));
		$db->setQuery($query);
		return (int) $db->loadResult() === 1;
	}

	/**
	 * "Activate protection": enables the system plugin, once nothing is
	 * missing (see missingForActivation()), and records it - in the setup
	 * state and in the User Actions Log.
	 */
	public function activate(?array $server = null): bool
	{
		$missing = $this->missingForActivation($server);
		if (count($missing) > 0)
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_ACTIVATE_ERROR_MISSING'));
			return false;
		}
		$db = $this->getDatabase();
		$query = $db->createQuery()
			->update($db->quoteName('#__extensions'))
			->set($db->quoteName('enabled') . ' = 1')
			->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
			->where($db->quoteName('folder') . ' = ' . $db->quote('system'))
			->where($db->quoteName('element') . ' = ' . $db->quote('bfstop'));
		$db->setQuery($query);
		$db->execute();
		if (!$this->pluginEnabled())
		{
			$this->setError(Text::_('COM_BFSTOP_SETUP_ACTIVATE_ERROR_PLUGIN'));
			return false;
		}
		// the list of enabled plugins may be cached (with the site's caching on)
		try
		{
			Factory::getContainer()->get(CacheControllerFactoryInterface::class)
				->createCacheController('callback', array('defaultgroup' => 'com_plugins'))->clean('com_plugins');
		}
		catch (\Throwable $e)
		{
			// then it expires on its own
		}
		$this->setupState()->complete();
		$this->saveSetupState();
		ActionLogHelper::log('protection_activated');
		return true;
	}

	/** "This is expected": the mismatch with the fingerprint $fingerprint isn't shown any more. */
	public function dismiss(string $fingerprint): void
	{
		$this->setupState()->dismiss($fingerprint);
		$this->saveSetupState();
	}

	/**
	 * Cloudflare's address ranges, fetched from cloudflare.com (only when the
	 * administrator asks for them): addresses and networks only, none wider
	 * than the trusted proxies may be (see ProxylistRule). Null if they
	 * can't be fetched, or something else came back.
	 *
	 * @return string[]|null
	 */
	public static function cloudflareRanges(): ?array
	{
		$ranges = array();
		try
		{
			$http = HttpFactory::getHttp();
			foreach (self::CloudflareRanges as $url)
			{
				$response = $http->get($url, array(), 10);
				if ((int) $response->getStatusCode() !== 200)
				{
					return null;
				}
				foreach (preg_split('/\s+/', trim((string) $response->getBody())) as $entry)
				{
					$parts = explode('/', $entry, 2);
					$minBits = str_contains($parts[0], ':') ? IpValidateHelper::MinPrefixIPv6 : IpValidateHelper::MinPrefixIPv4;
					if (!IpHelper::isValidIpOrSubnet($entry) || (count($parts) === 2 && (int) $parts[1] < $minBits) ||
						count($ranges) >= 200)
					{
						return null;
					}
					$ranges[] = IpHelper::canonicalEntry($entry);
				}
			}
		}
		catch (\Throwable $e)
		{
			return null;
		}
		return count($ranges) > 0 ? $ranges : null;
	}
}
