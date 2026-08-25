<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Controller;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Controller\AdminController;
use Joomla\CMS\Router\Route;

class HtblocklistController extends AdminController
{
	public function getModel($name = 'htblocklist', $prefix = 'bfstopmodel', $config = [])
	{
		$model = parent::getModel($name, $prefix, array('ignore_request' => true));
		return $model;
	}

	function unblock()
	{
		$logger = LogHelper::getLogger();
		$input = Factory::getApplication()->input;
		$ips = $input->post->get('cid', array(), 'array');
		$model = $this->getModel('htblocklist');
		$message = $model->unblock($ips, $logger);
		// redirect to htblocklist view
		$this->setRedirect(Route::_('index.php?option=com_bfstop&view=htblocklist', false),
			$message, 'notice');
	}
}
