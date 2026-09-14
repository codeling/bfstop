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
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\AdminController;
use Joomla\CMS\Router\Route;

class HtblocklistController extends AdminController
{
	public function getModel($name = 'htblocklist', $prefix = '', $config = [])
	{
		$model = parent::getModel($name, $prefix, array('ignore_request' => true));
		return $model;
	}

	function unblock()
	{
		// custom action, not AdminModel's standard delete() flow, so it
		// doesn't get the built-in core.delete check for free
		if (!Factory::getApplication()->getIdentity()->authorise('core.delete', 'com_bfstop'))
		{
			$this->setRedirect(Route::_('index.php?option=com_bfstop&view=htblocklist', false),
				Text::_('COM_BFSTOP_NOT_AUTHORISED'), 'error');
			return;
		}
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
