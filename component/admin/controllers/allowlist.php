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
use Joomla\Utilities\ArrayHelper;

class BFStopControllerAllowList extends AdminController
{
	public function getModel($name = 'allowlist', $prefix = 'bfstopmodel', $config = [])
	{
		$model = parent::getModel($name, $prefix, array('ignore_request' => true));
		return $model;
	}

	public function remove()
	{
		$logger = getLogger();
		$input =  Factory::getApplication()->input;
		$ids = $input->post->get('cid', array(), 'array');
		ArrayHelper::toInteger($ids);
		$model = $this->getModel('allowlist');
		$message = $model->remove($ids, $logger);
		$this->setRedirect(Route::_('index.php?option=com_bfstop&view=allowlist',false),
			$message, 'notice');
	}
}
