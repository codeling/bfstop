<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Controller;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ActionLogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Helper\NginxDenyFile;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;
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

	/**
	 * A block added or changed by hand goes into the User Actions Log.
	 */
	protected function postSaveHook(BaseDatabaseModel $model, $validData = array())
	{
		$id = (int) $model->getState($model->getName().'.id');
		$addresses = ActionLogHelper::addresses('#__bfstop_bannedip', array($id));
		// a block made or changed by hand goes into the nginx deny file as well
		NginxDenyFile::syncForSettings(Settings::stored(), new Repositories(LogHelper::getLogger()));
		ActionLogHelper::log($model->getState($model->getName().'.new') ? 'block_added' : 'block_changed', array(
			'id' => $id,
			'ipaddress' => $addresses[$id] ?? (string) ($validData['ipaddress'] ?? ''),
			'duration' => (string) ($validData['duration'] ?? ''),
		));
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
