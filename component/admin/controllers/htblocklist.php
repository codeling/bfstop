<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Controller\AdminController;
use Joomla\CMS\Router\Route;

class BFStopControllerHTBlockList extends AdminController
{
	public function getModel($name = 'htblocklist', $prefix = 'bfstopmodel', $config = [])
	{
		$model = parent::getModel($name, $prefix, array('ignore_request' => true));
		return $model;
	}

	function unblock()
	{
		$logger = getLogger();
		$input =  Factory::getApplication()->input;
		$ips = $input->post->get('cid', array(), 'array');
		$model = $this->getModel('htblocklist');
		$message = $model->unblock($ips, $logger);
		// redirect to htblocklist view
		$this->setRedirect(Route::_('index.php?option=com_bfstop&view=htblocklist',false),
			$message, 'notice');
	}
}
