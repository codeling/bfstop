<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Model\AdminModel;
use Joomla\CMS\Table\Table;

class BFStopModelAllow extends AdminModel
{
	public function getTable($type = 'allow', $prefix = 'BFStopTable', $config = array())
	{
		return Table::getInstance($type, $prefix, $config);
	}
	public function getForm($data = array(), $loadData = true)
	{
		$form = $this->loadForm('com_bfstop.allow', 'allow',
			array('control' => 'jform', 'load_data' => $loadData));
		if (empty($form))
		{
			return false;
		}
		return $form;
	}
	protected function loadFormData()
	{
		$data = Factory::getApplication()->getUserState('com_bfstop.edit.allow.data', array());
		if (empty($data))
		{
			$data = $this->getItem();
		}
		return $data;
	}
}
