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

class BFStopModelHTBlock extends AdminModel
{
	public function getItem($pk = NULL)
	{
		return array('ipaddress' => '0.0.0.0');
	}
	public function getForm($data = array(), $loadData = true)
	{
		$form = $this->loadForm('com_bfstop.htblock', 'htblock',
			array('control' => 'jform', 'load_data' => $loadData));
		if (empty($form))
		{
			return false;
		}
		return $form;
	}
	protected function loadFormData()
	{
		$data = Factory::getApplication()->getUserState('com_bfstop.edit.htblock.data', array());
		return $data;
	}
}
