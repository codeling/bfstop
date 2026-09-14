<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Model\AdminModel;
use Joomla\CMS\Table\Table;

class SettingsModel extends AdminModel
{
	public function getTable($type = 'Extension', $prefix = '\\Joomla\\CMS\\Table\\', $config = array())
	{
		return Table::getInstance($type, $prefix, $config);
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
		$data[$this->getTable()->getKeyName()] = $this->resolvePluginExtensionId();
		return parent::save($data);
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
