<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Extension\Bfstop;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Model\AdminModel;
use Joomla\CMS\Table\Extension;

class SettingsModel extends AdminModel
{
	// the settings are the plugin's row of Joomla's extensions table
	public function getTable($name = '', $prefix = '', $options = array())
	{
		return new Extension($this->getDatabase());
	}

	public function getForm($data = array(), $loadData = true)
	{
		$form = $this->loadForm('com_bfstop.settings', 'settings',
			array('control' => 'jform', 'load_data' => $loadData));
		if (empty($form))
		{
			return false;
		}
		return $form;
	}

	public function getItem($pk = null)
	{
		return parent::getItem($this->resolvePluginExtensionId());
	}

	// AdminModel's own loadFormData() default (via FormBehaviorTrait) always
	// returns an empty array, so without this override the settings form
	// would bind against nothing and every field would show its XML default
	// instead of the value actually stored on the plugin's #__extensions row.
	protected function loadFormData()
	{
		$data = Factory::getApplication()->getUserState('com_bfstop.edit.settings.data', array());
		if (empty($data))
		{
			$data = $this->getItem();
			if (is_object($data) && isset($data->params) && is_array($data->params))
			{
				$data->params = self::paramsForForm($data->params);
			}
		}
		return $data;
	}

	/**
	 * The stored params as the form shows them: "enabledForOrigin" is a
	 * bitmask (what the plugin reads, and what 1.x stored), the form has a
	 * checkbox for each of its bits.
	 */
	public static function paramsForForm(array $params)
	{
		$params['enabledForOrigin'] = Bfstop::originList(
			$params['enabledForOrigin'] ?? Bfstop::DefaultSettings['enabledForOrigin']);
		return $params;
	}

	/**
	 * The form's params as they are stored, see paramsForForm(). The form
	 * requires a part to be ticked; should a request come without any (or
	 * only with values which are none), the setting is left out, which makes
	 * the plugin use its default - active for all parts, not for none.
	 */
	public static function paramsForStorage(array $params)
	{
		if (array_key_exists('enabledForOrigin', $params))
		{
			$mask = Bfstop::originMask($params['enabledForOrigin']);
			if ($mask === 0)
			{
				unset($params['enabledForOrigin']);
			}
			else
			{
				$params['enabledForOrigin'] = $mask;
			}
		}
		return $params;
	}

	/**
	 * Unblock links for any IP address (Bfstop::NotifyBlockedAnyAddress) are
	 * only safe with the site's $live_site, see
	 * Bfstop::effectiveNotifyBlockedUser(): without it, the settings page
	 * doesn't take that value.
	 */
	public function validate($form, $data, $group = null)
	{
		$valid = parent::validate($form, $data, $group);
		if (is_array($valid) && !Bfstop::hasLiveSite() &&
			(int) ($valid['params']['notifyBlockedUser'] ?? 0) === Bfstop::NotifyBlockedAnyAddress)
		{
			$this->setError(Text::_('COM_BFSTOP_SETTINGS_NOTIFY_ANY_NEEDS_LIVE_SITE'));
			return false;
		}
		return $valid;
	}

	public function save($data)
	{
		$id = $this->resolvePluginExtensionId();
		$data[$this->getTable()->getKeyName()] = $id;
		$data['params'] = self::keepInternalSettings(self::paramsForStorage($data['params'] ?? array()),
			$this->loadStoredParams($id));
		return parent::save($data);
	}

	/**
	 * The form's values replace all the plugin's params when they are saved,
	 * so the values the plugin keeps there for itself (which the form doesn't
	 * have, Bfstop::InternalSettings) have to be put back in: without them,
	 * it would convert all stored addresses again on the next request and run
	 * its daily maintenance at once.
	 */
	public static function keepInternalSettings($params, array $stored)
	{
		$params = is_array($params) ? $params : array();
		foreach (Bfstop::InternalSettings as $name)
		{
			if (array_key_exists($name, $stored) && !array_key_exists($name, $params))
			{
				$params[$name] = $stored[$name];
			}
		}
		return $params;
	}

	private function loadStoredParams($id)
	{
		$table = $this->getTable();
		if (!$table->load($id))
		{
			return array();
		}
		$params = json_decode((string) $table->params, true);
		return is_array($params) ? $params : array();
	}

	// the "settings" being edited here are not stored in a table of this
	// component; they are the plugin's own params, on its #__extensions row.
	protected function resolvePluginExtensionId()
	{
		$table = $this->getTable();
		$table->load(array('name' => 'plg_system_bfstop'));
		return (int) $table->extension_id;
	}

	// the default cleanCache() only clears the "com_bfstop" group, but the
	// enabled-plugins list (with params) that PluginHelper::getPlugin() reads
	// at runtime is cached under "com_plugins" - without this override, a
	// saved change here (e.g. to the proxy/load balancer settings) wouldn't
	// actually take effect until that separate cache expired on its own.
	protected function cleanCache($group = null)
	{
		parent::cleanCache('com_plugins');
	}
}
