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
		}
		return $data;
	}

	public function save($data)
	{
		$id = $this->resolvePluginExtensionId();
		$data[$this->getTable()->getKeyName()] = $id;
		$data['params'] = self::keepInternalSettings($data['params'] ?? array(), $this->loadStoredParams($id));
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
