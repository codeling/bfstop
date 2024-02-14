<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\MVC\Controller\FormController;

class BFStopControllerBlock extends FormController
{
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
