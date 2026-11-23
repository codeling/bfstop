<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\View\Setup;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Controller\SetupController;
use Codeling\Component\Bfstop\Administrator\Helper\VersionHelper;
use Codeling\Component\Bfstop\Administrator\Model\SetupModel;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Service\Setup\ProxyDetector;
use Codeling\Library\Bfstop\Service\Setup\SetupState;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Access\Exception\NotAllowed;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Toolbar\ToolbarHelper;
use Joomla\CMS\Version;
use Joomla\Registry\Registry;

/**
 * The setup assistant (see SetupModel): a page per step, and the steps with
 * their state at the side.
 */
class HtmlView extends BaseHtmlView
{
	protected string $page = 'overview';
	protected SetupState $setup;
	protected array $detected = array();
	protected array $proposal = array();
	protected ?array $proxyInput = null;
	protected ?array $preview = null;
	protected array $mismatches = array();
	protected array $blocking = array();
	protected array $advice = array();
	protected array $missing = array();
	protected bool $pluginEnabled = false;
	protected Registry $settings;
	protected ?string $loadBalancerHint = null;
	protected string $issueUrl = '';

	public function display($tpl = null)
	{
		// it changes the settings and enables the plugin: for who may change
		// the settings, as the settings page
		if (!Factory::getApplication()->getIdentity()->authorise('core.admin', 'com_bfstop'))
		{
			throw new NotAllowed(Text::_('JERROR_ALERTNOAUTHOR'), 403);
		}
		// the labels of the settings (shown with the values which keep them
		// from being saved) are the plugin's, see the settings page
		$language = Factory::getApplication()->getLanguage();
		$language->load('plg_system_bfstop.sys', JPATH_ADMINISTRATOR)
			|| $language->load('plg_system_bfstop.sys', JPATH_PLUGINS.'/system/bfstop');

		$model = $this->getModel();
		if (!$model instanceof SetupModel)
		{
			throw new \RuntimeException('The model of the setup assistant is missing');
		}
		$page = Factory::getApplication()->getInput()->getCmd('page', 'overview');
		$this->page = in_array($page, SetupModel::Pages, true) ? $page : 'overview';
		$this->setup = $model->setupState();
		$this->settings = new Registry($model->storedParams());
		$this->detected = $model->detection();
		$this->proposal = ProxyDetector::proposal($this->detected);
		$this->mismatches = $model->mismatches();
		$this->blocking = $model->blockingValues();
		$this->advice = $model->blockModeAdvice();
		$this->missing = $model->missingForActivation();
		$this->pluginEnabled = $model->pluginEnabled();
		$this->loadBalancerHint = ProxyDetector::loadBalancerHint((bool) $this->setting('useProxy'), $this->detected['scenario'],
			SetupModel::behindLoadBalancer());
		$this->issueUrl = self::issueUrl($this->detected);

		// what the proxy step was given to check (see SetupController::preview())
		$app = Factory::getApplication();
		$input = $app instanceof CMSApplication ? $app->getUserState(SetupController::ProxyUserState) : null;
		$this->proxyInput = is_array($input) ? $input : null;
		if ($this->proxyInput !== null && !empty($this->proxyInput['previewed']) && $this->proxyInput['header'] !== '')
		{
			$this->preview = ProxyDetector::preview($_SERVER, true, (string) $this->proxyInput['header'],
				(string) $this->proxyInput['trusted']);
		}

		$this->addToolbar();
		parent::display($tpl);
	}

	/**
	 * The status of the page $page in the list of steps: done, skipped or
	 * pending (the pages which are no step: none).
	 */
	public function pageStatus(string $page): ?string
	{
		if (!isset(SetupModel::PageSteps[$page]))
		{
			return null;
		}
		return $this->setup->status(SetupModel::PageSteps[$page]);
	}

	/** The name of the header of the $_SERVER key $key, see IpHelper::headerName(). */
	public static function headerName(string $key): string
	{
		return IpHelper::headerName($key);
	}

	/**
	 * The link which opens a new issue in BFStop's bug tracker, about headers
	 * BFStop doesn't read: with their names, the scenario and the versions
	 * of BFStop and Joomla, nothing else - no values, addresses or the
	 * site's address. The administrator opens it; the site sends nothing.
	 */
	public static function issueUrl(array $detected): string
	{
		$versions = VersionHelper::getInstalledVersions();
		$body = "Brute Force Stop doesn't read the header(s) my proxy sends.\n\n".
			'- Headers BFStop does not read: '.implode(', ', array_values($detected['unsupported']))."\n".
			'- Headers BFStop reads: '.implode(', ', array_map(array(IpHelper::class, 'headerName'),
				array_keys($detected['supported'])))."\n".
			'- Detected scenario: '.$detected['scenario']."\n".
			'- BFStop: '.(string) $versions['component']."\n".
			'- Joomla: '.(new Version())->getShortVersion()."\n\n".
			"What is in front of the site (proxy, CDN, hosting):\n";
		return 'https://github.com/codeling/bfstop/issues/new?'.http_build_query(array(
			'title' => 'Proxy header not supported: '.implode(', ', array_values($detected['unsupported'])),
			'body' => $body,
		));
	}

	/** A setting, as Settings::get() reads it. */
	public function setting(string $name)
	{
		return Settings::get($this->settings, $name);
	}

	protected function addToolbar()
	{
		ToolbarHelper::title(Text::_('COM_BFSTOP_HEADING_SETUP'), 'bfstop');
		ToolbarHelper::link('index.php?option=com_bfstop&view=settings', 'COM_BFSTOP_SETUP_TO_SETTINGS', 'options');
	}
}
