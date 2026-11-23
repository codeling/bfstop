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
use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\Setup\ProxyDetector;
use Codeling\Library\Bfstop\Service\Setup\ProxyMismatch;
use Codeling\Library\Bfstop\Service\Setup\SettingsAudit;
use Codeling\Library\Bfstop\Service\Setup\SetupState;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Cache\CacheControllerFactoryInterface;
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
	/** the pages of the assistant, in their order */
	public const Pages = array('overview', 'proxy', 'blockmode', 'summary');

	/** the step of the setup state each page stands for (the others stand for none) */
	public const PageSteps = array('proxy' => SetupState::StepProxy, 'blockmode' => SetupState::StepBlockMode);

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
