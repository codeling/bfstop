<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Controller;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use Joomla\CMS\MVC\Controller\FormController;

class BlockController extends FormController
{
	/**
	 * Blocks of networks wider than this (IPv4 / IPv6 prefix length) need
	 * core.admin as well: a /16 shuts out whole providers, and nobody in it
	 * can lift the block from within the site. (Narrower than /8 or /16 they
	 * can't be anyway, see IpValidateHelper.)
	 */
	public const WideNetworkPrefixIPv4 = 24;
	public const WideNetworkPrefixIPv6 = 48;

	/**
	 * Whether $ipaddress is a network wider than WideNetworkPrefix*.
	 */
	public static function isWideNetwork($ipaddress)
	{
		$canonical = IpHelper::canonicalEntry((string) $ipaddress);
		if ($canonical === null || strpos($canonical, '/') === false)
		{
			return false;
		}
		list($address, $bits) = explode('/', $canonical);
		return (int) $bits < (strpos($address, ':') !== false ? self::WideNetworkPrefixIPv6 : self::WideNetworkPrefixIPv4);
	}

	protected function allowSave($data, $key = 'id')
	{
		if (!parent::allowSave($data, $key))
		{
			return false;
		}
		if (!self::isWideNetwork($data['ipaddress'] ?? ''))
		{
			return true;
		}
		$user = $this->app->getIdentity();
		return $user && $user->authorise('core.admin', $this->option);
	}

	public function save($key = null, $urlVar = null)
	{
		$return = parent::save($key, $urlVar);
		$this->setRedirect('index.php?option=com_bfstop&view=blocklist');
		return $return;
	}

	public function cancel($key = null)
	{
		$return = parent::cancel($key);
		$this->setRedirect('index.php?option=com_bfstop&view=blocklist');
		return $return;
	}
}
