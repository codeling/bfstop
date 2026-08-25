<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

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
}
