<?php
/*
 * @package BFStop Quick Icon Plugin (plg_quickicon_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\Quickicon\Bfstop\Extension;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\Setup\ProxyDetector;
use Codeling\Library\Bfstop\Service\Setup\ProxyMismatch;
use Codeling\Library\Bfstop\Service\Setup\SetupState;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Event\SubscriberInterface;
use Joomla\Module\Quickicon\Administrator\Event\QuickIconsEvent;

/**
 * A tile of Brute Force Stop on the Home Dashboard, in the notification area
 * where Joomla's own status tiles are: whether protection is active, and
 * whether the administrator's own request fits the proxy settings (the
 * library's ProxyMismatch, as the banner of the BFStop backend). Hosting
 * changes without anybody telling BFStop, and nobody opens its pages to
 * find out. One query (the setup state), only when a dashboard is shown, and
 * only for who may change the settings: the others see the plain tile.
 */
final class Bfstop extends CMSPlugin implements SubscriberInterface
{
	protected $autoloadLanguage = true;

	// what the tile says, see tile()
	public const Inactive = 'inactive';
	public const Incomplete = 'incomplete';
	public const Mismatch = 'mismatch';
	public const Fine = 'fine';

	public static function getSubscribedEvents(): array
	{
		// without the library there is nothing to show
		if (!class_exists(SetupState::class))
		{
			return array();
		}
		return array('onGetIcons' => 'onGetIcons');
	}

	public function onGetIcons(QuickIconsEvent $event): void
	{
		$app = $this->getApplication();
		if ($event->getContext() !== $this->params->get('context', 'update_quickicon') || !$app->isClient('administrator'))
		{
			return;
		}
		$user = $app->getIdentity();
		if (!$user || !$user->authorise('core.manage', 'com_bfstop'))
		{
			return;
		}
		$state = self::Fine;
		if ($user->authorise('core.admin', 'com_bfstop'))
		{
			$setup = SetupState::load((new Repositories(LoggerHelper::fromSettings(Settings::held())))->state());
			$mismatches = ProxyMismatch::open(ProxyMismatch::check($_SERVER, ProxyDetector::proxySettings(Settings::held()),
				(bool) $app->get('behind_loadbalancer', 0), $setup), true);
			$state = self::state(PluginHelper::isEnabled('system', 'bfstop'), $setup->isCompleted(), count($mismatches) > 0);
		}
		$result = $event->getArgument('result', array());
		$result[] = array(self::tile($state, $app->getLanguage()->_('PLG_QUICKICON_BFSTOP_'.strtoupper($state))));
		$event->setArgument('result', $result);
	}

	/**
	 * What the tile says (highest priority first): Inactive (the system
	 * plugin is missing or disabled), Incomplete (it runs, but the setup
	 * assistant hasn't been completed), Mismatch (a mismatch of the proxy
	 * settings which hasn't been dismissed), Fine.
	 */
	public static function state(bool $pluginEnabled, bool $setupCompleted, bool $mismatch): string
	{
		if (!$pluginEnabled)
		{
			return self::Inactive;
		}
		if (!$setupCompleted)
		{
			return self::Incomplete;
		}
		return $mismatch ? self::Mismatch : self::Fine;
	}

	/**
	 * The tile (see Joomla's layout joomla.quickicons.icon) of the state
	 * $state, with the text $text: an error links to the setup assistant, a
	 * mismatch to its proxy step, the plain tile to the component.
	 */
	public static function tile(string $state, string $text): array
	{
		$links = array(
			self::Inactive => 'index.php?option=com_bfstop&view=setup',
			self::Incomplete => 'index.php?option=com_bfstop&view=setup',
			self::Mismatch => 'index.php?option=com_bfstop&view=setup&page=proxy',
			self::Fine => 'index.php?option=com_bfstop',
		);
		$classes = array(self::Inactive => 'danger', self::Incomplete => 'danger', self::Mismatch => 'warning', self::Fine => 'success');
		return array(
			'link' => $links[$state],
			'image' => 'icon-shield-alt',
			'text' => htmlspecialchars($text, ENT_QUOTES, 'UTF-8'),
			'class' => $classes[$state],
			'id' => 'plg_quickicon_bfstop',
			'group' => 'MOD_QUICKICON_MAINTENANCE',
		);
	}
}
